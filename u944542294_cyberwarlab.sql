-- phpMyAdmin SQL Dump
-- version 5.2.2
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1:3306
-- Generation Time: Mar 02, 2026 at 10:14 AM
-- Server version: 11.8.3-MariaDB-log
-- PHP Version: 7.2.34

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `u944542294_cyberwarlab`
--

DELIMITER $$
--
-- Procedures
--
CREATE DEFINER=`u944542294_cyberwarlab`@`127.0.0.1` PROCEDURE `CleanupExpiredNonces` ()   BEGIN
  -- Mark expired nonces as used for audit
  UPDATE file_access_nonces
  SET used = 1, used_at = NOW()
  WHERE expires_at < NOW() AND used = 0;

  -- Delete very old used nonces (older than 7 days)
  DELETE FROM file_access_nonces
  WHERE used = 1 AND used_at < DATE_SUB(NOW(), INTERVAL 7 DAY);

  -- Cleanup old rate limit records (older than 1 hour)
  DELETE FROM rate_limits
  WHERE window_start < DATE_SUB(NOW(), INTERVAL 1 HOUR);

  -- Cleanup old security events (older than 30 days)
  DELETE FROM enhanced_security_events
  WHERE created_at < DATE_SUB(NOW(), INTERVAL 30 DAY);
END$$

CREATE DEFINER=`u944542294_cyberwarlab`@`127.0.0.1` PROCEDURE `CleanupExpiredSessions` ()   BEGIN
  -- Mark expired sessions as inactive
  UPDATE user_sessions
  SET is_active = 0
  WHERE expires_at < NOW() AND is_active = 1;

  -- Delete very old inactive sessions (older than 30 days)
  DELETE FROM user_sessions
  WHERE is_active = 0
  AND last_activity < DATE_SUB(NOW(), INTERVAL 30 DAY);

  -- Reset failed attempts for unlocked accounts
  UPDATE users
  SET failed_attempts = 0, locked_until = NULL
  WHERE locked_until IS NOT NULL
  AND locked_until < NOW();
END$$

CREATE DEFINER=`u944542294_cyberwarlab`@`127.0.0.1` PROCEDURE `GenerateAcademyCertificate` (IN `user_id_param` INT, IN `course_id_param` INT, IN `exam_package_id_param` INT)   BEGIN
  DECLARE cert_number VARCHAR(100);
  DECLARE verification_code VARCHAR(100);
  DECLARE course_title VARCHAR(500);

  -- Generate certificate number
  SET cert_number = CONCAT('CWL-', DATE_FORMAT(NOW(), '%Y'), '-', LPAD(user_id_param, 6, '0'), '-', LPAD(course_id_param, 4, '0'));

  -- Generate verification code
  SET verification_code = UPPER(SUBSTRING(MD5(CONCAT(user_id_param, course_id_param, NOW())), 1, 12));

  -- Get course title
  IF course_id_param IS NOT NULL THEN
    SELECT title INTO course_title FROM courses WHERE id = course_id_param;
  ELSE
    SELECT package_name INTO course_title FROM exam_packages WHERE id = exam_package_id_param;
  END IF;

  -- Insert certificate
  INSERT IGNORE INTO academy_certificates (user_id, course_id, exam_package_id, certificate_number, verification_code, title)
  VALUES (user_id_param, course_id_param, exam_package_id_param, cert_number, verification_code, course_title);

  -- Update purchased_courses
  UPDATE academy_purchased_courses
  SET certificate_issued = TRUE,
      certificate_number = cert_number,
      issued_at = NOW(),
      completion_date = CURDATE()
  WHERE user_id = user_id_param AND course_id = course_id_param;
END$$

CREATE DEFINER=`u944542294_cyberwarlab`@`127.0.0.1` PROCEDURE `GenerateFileAccessNonce` (IN `p_user_id` INT, IN `p_file_id` INT, IN `p_folder_id` INT, IN `p_ip_address` VARCHAR(45), IN `p_user_agent` TEXT, OUT `p_nonce` VARCHAR(32), OUT `p_token_hash` VARCHAR(64))   BEGIN
    DECLARE v_nonce VARCHAR(32);
    DECLARE v_secret_key VARCHAR(255);

    -- Generate cryptographically secure nonce
    SET v_nonce = SHA2(CONCAT(p_user_id, p_file_id, p_folder_id, NOW(), UUID()), 256);

    -- Get secret key (in production, this should be from secure config)
    SET v_secret_key = 'CyberWarLab_Nonce_Secret_2024';

    -- Generate token hash
    SET p_token_hash = SHA2(CONCAT(v_nonce, p_file_id, p_user_id, p_ip_address, v_secret_key), 256);
    SET p_nonce = v_nonce;

    -- Store in secure_preview_tokens table
    INSERT INTO secure_preview_tokens (
        token_hash, user_id, file_id, session_id, ip_address, user_agent_hash, expires_at
    ) VALUES (
        p_token_hash, p_user_id, p_file_id, SESSION_ID(), p_ip_address, SHA2(p_user_agent, 256), DATE_ADD(NOW(), INTERVAL 10 MINUTE)
    ) ON DUPLICATE KEY UPDATE
        token_hash = VALUES(token_hash),
        expires_at = VALUES(expires_at);
END$$

CREATE DEFINER=`u944542294_cyberwarlab`@`127.0.0.1` PROCEDURE `GetUserExamStats` (IN `user_id` INT)   BEGIN
    SELECT 
        COUNT(*) as total_exams,
        SUM(CASE WHEN result = 'pass' THEN 1 ELSE 0 END) as passed_exams,
        SUM(CASE WHEN result = 'fail' THEN 1 ELSE 0 END) as failed_exams,
        AVG(CASE WHEN score IS NOT NULL THEN score END) as average_score,
        MAX(completed_at) as last_exam_date
    FROM exam_sessions 
    WHERE user_id = user_id AND status = 'completed';
END$$

CREATE DEFINER=`u944542294_cyberwarlab`@`127.0.0.1` PROCEDURE `MigrateExamPackagesToAcademy` ()   BEGIN
  DECLARE done INT DEFAULT FALSE;
  DECLARE pkg_id INT;
  DECLARE pkg_title VARCHAR(500);
  DECLARE pkg_description TEXT;
  DECLARE pkg_price DECIMAL(10,2);
  DECLARE pkg_category VARCHAR(50);
  DECLARE pkg_purchase_count INT;

  DECLARE package_cursor CURSOR FOR
    SELECT ep.id, ep.title, ep.description, ep.price, ep.category,
           COUNT(up.id) as purchase_count
    FROM exam_packages ep
    LEFT JOIN user_purchases up ON ep.id = up.package_id AND up.status = 'completed'
    WHERE ep.id NOT IN (
      SELECT exam_package_id FROM course_package_mapping WHERE status = 'active'
    )
    GROUP BY ep.id
    ORDER BY purchase_count DESC, ep.id;

  DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = TRUE;

  OPEN package_cursor;

  read_loop: LOOP
    FETCH package_cursor INTO pkg_id, pkg_title, pkg_description, pkg_price, pkg_category, pkg_purchase_count;
    IF done THEN
      LEAVE read_loop;
    END IF;

    -- Create academy course if there are purchases
    IF pkg_purchase_count > 0 THEN
      INSERT INTO courses (title, description, price, category, status, enrollments, source_package_id)
      VALUES (pkg_title, pkg_description, pkg_price, pkg_category, 'published', pkg_purchase_count, pkg_id);

      SET @course_id = LAST_INSERT_ID();

      -- Update mapping
      INSERT INTO course_package_mapping (exam_package_id, academy_course_id, title, map_type, status)
      VALUES (pkg_id, @course_id, pkg_title, 'integrate', 'active');
    END IF;

  END LOOP;

  CLOSE package_cursor;
END$$

CREATE DEFINER=`u944542294_cyberwarlab`@`127.0.0.1` PROCEDURE `UpdateAcademyCourseProgress` (IN `user_id_param` INT, IN `course_id_param` INT)   BEGIN
  DECLARE total_lessons_val INT DEFAULT 0;
  DECLARE completed_lessons_val INT DEFAULT 0;
  DECLARE progress_val INT DEFAULT 0;

  -- Get total lessons for the course
  SELECT COUNT(DISTINCT l.id) INTO total_lessons_val
  FROM course_lessons l
  JOIN course_sections cs ON l.section_id = cs.id
  WHERE cs.course_id = course_id_param AND l.status = 'active';

  -- Get completed lessons for the user
  SELECT COUNT(DISTINCT ul.lesson_id) INTO completed_lessons_val
  FROM user_lessons ul
  WHERE ul.user_id = user_id_param;

  -- Calculate progress
  IF total_lessons_val > 0 THEN
    SET progress_val = ROUND((completed_lessons_val / total_lessons_val) * 100);
  END IF;

  -- Update academy_purchased_courses table
  UPDATE academy_purchased_courses
  SET progress = progress_val,
      completed_lessons = completed_lessons_val,
      total_lessons = total_lessons_val,
      last_accessed = NOW()
  WHERE user_id = user_id_param AND course_id = course_id_param;

  -- Check if certificate should be issued
  IF progress_val >= 100 THEN
    UPDATE academy_purchased_courses
    SET certificate_issued = 1,
        issued_at = NOW(),
        completion_date = CURDATE()
    WHERE user_id = user_id_param AND course_id = course_id_param
    AND certificate_issued = 0;
  END IF;

  SELECT progress_val as progress, completed_lessons_val, total_lessons_val;
END$$

CREATE DEFINER=`u944542294_cyberwarlab`@`127.0.0.1` PROCEDURE `UpdateCourseProgress` (IN `user_id_param` INT, IN `course_id_param` INT)   BEGIN
  DECLARE total_lessons_val INT DEFAULT 0;
  DECLARE completed_lessons_val INT DEFAULT 0;
  DECLARE progress_val INT DEFAULT 0;

  -- Get total lessons for the course
  SELECT COUNT(DISTINCT l.id) INTO total_lessons_val
  FROM course_lessons l
  JOIN course_sections cs ON l.section_id = cs.id
  WHERE cs.course_id = course_id_param AND l.status = 'active';

  -- Get completed lessons for the user
  SELECT COUNT(DISTINCT ul.lesson_id) INTO completed_lessons_val
  FROM user_lessons ul
  WHERE ul.user_id = user_id_param;

  -- Calculate progress
  IF total_lessons_val > 0 THEN
    SET progress_val = ROUND((completed_lessons_val / total_lessons_val) * 100);
  END IF;

  -- Update purchased_courses table
  UPDATE purchased_courses
  SET progress = progress_val,
      completed_lessons = completed_lessons_val,
      total_lessons = total_lessons_val,
      last_accessed = NOW()
  WHERE user_id = user_id_param AND course_id = course_id_param;

  SELECT progress_val as progress, completed_lessons_val, total_lessons_val;
END$$

--
-- Functions
--
CREATE DEFINER=`u944542294_cyberwarlab`@`127.0.0.1` FUNCTION `generate_client_access_key` () RETURNS VARCHAR(32) CHARSET utf8mb4 COLLATE utf8mb4_unicode_ci DETERMINISTIC BEGIN
    DECLARE key_str varchar(32);
    REPEAT
        SET key_str = MD5(CONCAT(RAND(), NOW(), UUID()));
    UNTIL NOT EXISTS (
        SELECT 1 FROM contact_messages WHERE client_access_key = key_str
    ) END REPEAT;
    RETURN key_str;
END$$

DELIMITER ;

-- --------------------------------------------------------

--
-- Table structure for table `academy_access`
--

CREATE TABLE `academy_access` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `certificate_id` int(11) DEFAULT NULL COMMENT 'If accessed via certificate purchase',
  `access_type` enum('purchase','grant','trial') NOT NULL DEFAULT 'purchase',
  `access_status` enum('active','expired','revoked') NOT NULL DEFAULT 'active',
  `expires_at` timestamp NULL DEFAULT NULL,
  `granted_by` int(11) DEFAULT NULL COMMENT 'Admin ID if granted manually',
  `notes` text DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `academy_access`
--

INSERT INTO `academy_access` (`id`, `user_id`, `certificate_id`, `access_type`, `access_status`, `expires_at`, `granted_by`, `notes`, `created_at`, `updated_at`) VALUES
(1, 27, 2, 'purchase', 'active', NULL, NULL, 'Access granted via purchase of: CEHS', '2025-12-02 05:16:33', '2025-12-02 05:16:33'),
(2, 27, 2, 'purchase', 'active', NULL, NULL, 'Access granted via purchase of: CEHS', '2025-12-02 05:16:53', '2025-12-02 05:16:53'),
(3, 27, 2, 'purchase', 'active', NULL, NULL, 'Access granted via purchase of: CEHS', '2025-12-02 05:16:57', '2025-12-02 05:16:57'),
(4, 27, 2, 'purchase', 'active', NULL, NULL, 'Access granted via purchase of: CEHS', '2025-12-02 05:18:04', '2025-12-02 05:18:04'),
(5, 27, 2, 'purchase', 'active', NULL, NULL, 'Access granted via purchase of: CEHS', '2025-12-02 05:18:05', '2025-12-02 05:18:05'),
(6, 27, 2, 'purchase', 'active', NULL, NULL, 'Access granted via purchase of: CEHS', '2025-12-02 05:18:08', '2025-12-02 05:18:08'),
(7, 27, 2, 'purchase', 'active', NULL, NULL, 'Access granted via purchase of: CEHS', '2025-12-02 05:21:06', '2025-12-02 05:21:06'),
(8, 27, 2, 'purchase', 'active', NULL, NULL, 'Access granted via purchase of: CEHS', '2025-12-02 05:21:07', '2025-12-02 05:21:07'),
(9, 27, 2, 'purchase', 'active', NULL, NULL, 'Access granted via purchase of: CEHS', '2025-12-02 05:22:21', '2025-12-02 05:22:21'),
(10, 27, 2, 'purchase', 'active', NULL, NULL, 'Access granted via purchase of: CEHS', '2025-12-02 05:25:56', '2025-12-02 05:25:56'),
(11, 27, 2, 'purchase', 'active', NULL, NULL, 'Access granted via purchase of: CEHS', '2025-12-02 05:25:57', '2025-12-02 05:25:57');

-- --------------------------------------------------------

--
-- Table structure for table `academy_access_logs`
--

CREATE TABLE `academy_access_logs` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `file_id` int(11) DEFAULT NULL,
  `content_id` int(11) DEFAULT NULL,
  `action` varchar(50) NOT NULL DEFAULT 'view',
  `ip_address` varchar(45) DEFAULT NULL,
  `user_agent` text DEFAULT NULL,
  `access_time` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `academy_certificates`
--

CREATE TABLE `academy_certificates` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `course_id` int(11) DEFAULT NULL,
  `exam_package_id` int(11) DEFAULT NULL,
  `certificate_number` varchar(100) NOT NULL,
  `verification_code` varchar(100) NOT NULL,
  `title` varchar(500) DEFAULT NULL,
  `description` text DEFAULT NULL,
  `score` decimal(5,2) DEFAULT NULL,
  `total_score` decimal(5,2) DEFAULT 100.00,
  `completion_date` date DEFAULT NULL,
  `issued_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `expires_at` timestamp NULL DEFAULT NULL,
  `status` enum('active','expired','revoked') DEFAULT 'active',
  `certificate_url` varchar(500) DEFAULT NULL,
  `pdf_path` varchar(500) DEFAULT NULL,
  `template_used` varchar(100) DEFAULT 'default',
  `instructor_signature` varchar(200) DEFAULT NULL,
  `institution_name` varchar(200) DEFAULT 'CyberWarLab Academy',
  `qr_code_url` varchar(500) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `academy_content`
--

CREATE TABLE `academy_content` (
  `id` int(11) NOT NULL,
  `section_id` int(11) NOT NULL,
  `title` varchar(255) NOT NULL,
  `description` text DEFAULT NULL,
  `content_type` enum('video','document','resource','quiz','assignment') NOT NULL DEFAULT 'video',
  `lms_file_path` varchar(500) DEFAULT NULL,
  `lms_folder_path` varchar(500) DEFAULT NULL,
  `content_url` varchar(500) DEFAULT NULL,
  `lms_file_id` int(11) DEFAULT NULL,
  `duration_minutes` int(11) DEFAULT NULL,
  `sort_order` int(11) NOT NULL DEFAULT 0,
  `is_preview_allowed` tinyint(1) NOT NULL DEFAULT 0,
  `download_allowed` tinyint(1) NOT NULL DEFAULT 0,
  `status` enum('active','inactive') NOT NULL DEFAULT 'active',
  `created_by` int(11) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `academy_content`
--

INSERT INTO `academy_content` (`id`, `section_id`, `title`, `description`, `content_type`, `lms_file_path`, `lms_folder_path`, `content_url`, `lms_file_id`, `duration_minutes`, `sort_order`, `is_preview_allowed`, `download_allowed`, `status`, `created_by`, `created_at`, `updated_at`) VALUES
(1, 1, 'Course Introduction', 'Welcome to the academy and overview of the course structure', 'video', NULL, NULL, NULL, NULL, 10, 1, 0, 0, '', NULL, '2025-12-02 05:18:22', '2025-12-03 07:03:32'),
(2, 1, 'What is Ethical Hacking?', 'Understanding the role and responsibilities of an ethical hacker', 'video', NULL, NULL, NULL, NULL, 15, 2, 0, 0, '', NULL, '2025-12-02 05:18:22', '2025-12-03 07:07:07'),
(3, 2, 'Passive Reconnaissance', 'Gathering information without directly interacting with the target', 'video', NULL, NULL, NULL, NULL, 25, 1, 0, 0, '', NULL, '2025-12-02 05:18:22', '2025-12-03 07:07:10'),
(4, 2, 'Active Reconnaissance', 'Direct engagement techniques for information gathering', 'video', NULL, NULL, NULL, NULL, 30, 2, 0, 0, '', NULL, '2025-12-02 05:18:22', '2025-12-03 07:07:10'),
(5, 3, 'Network Scanning Basics', 'Introduction to network scanning tools and techniques', 'video', NULL, NULL, NULL, NULL, 20, 1, 0, 0, '', NULL, '2025-12-02 05:18:22', '2025-12-03 07:07:12'),
(6, 1, 'Course Introduction', 'Welcome to the academy and overview of the course structure', 'video', NULL, NULL, NULL, NULL, 10, 1, 0, 0, '', NULL, '2025-12-02 05:22:25', '2025-12-03 07:07:07'),
(7, 1, 'What is Ethical Hacking?', 'Understanding the role and responsibilities of an ethical hacker', 'video', NULL, NULL, NULL, NULL, 15, 2, 0, 0, '', NULL, '2025-12-02 05:22:25', '2025-12-03 07:07:07'),
(8, 2, 'Passive Reconnaissance', 'Gathering information without directly interacting with the target', 'video', NULL, NULL, NULL, NULL, 25, 1, 0, 0, '', NULL, '2025-12-02 05:22:25', '2025-12-03 07:07:10'),
(9, 2, 'Active Reconnaissance', 'Direct engagement techniques for information gathering', 'video', NULL, NULL, NULL, NULL, 30, 2, 0, 0, '', NULL, '2025-12-02 05:22:25', '2025-12-03 07:07:10'),
(10, 3, 'Network Scanning Basics', 'Introduction to network scanning tools and techniques', 'video', NULL, NULL, NULL, NULL, 20, 1, 0, 0, '', NULL, '2025-12-02 05:22:25', '2025-12-03 07:07:12'),
(11, 6, 'asfd asfdas', 'fasfafafasffas', 'video', NULL, NULL, '../uploads/lms/1/1764604244_692db9548696d.mp4', 195, 9, 0, 0, 0, '', NULL, '2025-12-04 04:33:16', '2025-12-04 05:28:28'),
(12, 6, ' fasfasfasfasasf asdfasf', 'asdf asfdasf ', 'video', NULL, NULL, '../uploads/lms/1/1764603972_692db8443b1fb.mp4', 175, 11, 0, 0, 0, '', NULL, '2025-12-04 04:37:40', '2025-12-04 05:28:31'),
(13, 6, 'asfd asfdas', 'fasfafafasffas', 'video', NULL, NULL, 'LMS_FILE:174', 174, 9, 0, 0, 0, '', NULL, '2025-12-04 05:12:16', '2025-12-04 05:12:25'),
(14, 6, 'asfd asfdas', 'fasfafafasffas', 'video', NULL, NULL, 'LMS_FILE:146', 146, 9, 0, 0, 0, '', NULL, '2025-12-04 05:14:03', '2025-12-04 05:24:07'),
(15, 6, 'asfd asfdas', 'fasfafafasffas', 'video', NULL, NULL, 'LMS_FILE:146', 146, 9, 0, 0, 0, '', NULL, '2025-12-04 05:14:58', '2025-12-04 05:24:01'),
(16, 6, 'asdf asdfasfaf', 'asfasfasfasf', 'video', NULL, NULL, 'LMS_FILE:150', 150, 565, 0, 0, 0, '', NULL, '2025-12-04 05:28:07', '2025-12-04 05:30:54'),
(17, 6, ' sdfasfsafafas fdasdf ', 'asf asfffasfasf', 'video', NULL, NULL, 'LMS_FILE:191', 191, 524, 0, 0, 0, '', NULL, '2025-12-04 05:31:30', '2025-12-04 06:28:18'),
(18, 6, ' fasfdfasfdasfd', 'asfasfasf', 'video', NULL, NULL, 'LMS_FILE:150', 150, 0, 0, 0, 0, '', NULL, '2025-12-04 05:50:58', '2025-12-04 06:28:21'),
(19, 6, ' fasfdfasfdasfd', 'asfasfasf', 'video', NULL, NULL, '../uploads/lms/1/1764603199_692db53f503fa.mp4', 150, 0, 0, 0, 0, '', NULL, '2025-12-04 06:28:14', '2025-12-04 06:28:24'),
(20, 6, ' fasdfasfasf', ' asdfsafasf', 'video', NULL, NULL, '../uploads/lms/1/1764604188_692db91c68571.mp4', 191, 0, 0, 0, 0, '', NULL, '2025-12-04 06:28:38', '2025-12-05 05:40:54'),
(21, 6, ' adfasfdafasfd', ' asfdasfdasd', 'video', NULL, NULL, '../uploads/lms/1/1764603368_692db5e845a56.mp4', 153, 0, 0, 0, 0, '', NULL, '2025-12-05 04:24:29', '2025-12-05 04:44:24'),
(22, 6, ' adfasfdafasfd', ' asfdasfdasd', 'video', NULL, NULL, 'academy/secure_preview.php?file_id=153&token=DYNAMIC_TOKEN&file_name=automated+testing.mp4&file_type=video', 153, 0, 0, 0, 0, '', NULL, '2025-12-05 04:44:14', '2025-12-05 05:04:45'),
(23, 6, ' asfdasfdasfdasfdasdf as', 'dfasfasfasfa', 'video', NULL, NULL, 'SECURE_LMS_FILE:170:burp+suite+1.mp4:video', 170, 0, 0, 0, 0, '', NULL, '2025-12-05 04:48:47', '2025-12-05 05:04:51'),
(24, 6, 'safd asfdsafd', 'sa asfasfdasfd', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=195&token=DYNAMIC', 195, 0, 0, 0, 0, '', NULL, '2025-12-05 04:54:30', '2025-12-05 05:04:40'),
(25, 6, 'safd asfdsafd', 'sa asfasfdasfd', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=195&token=DYNAMIC', 195, 0, 0, 0, 0, '', NULL, '2025-12-05 05:04:32', '2025-12-05 05:04:55'),
(26, 6, ' asfdasfasdf as', ' asdf asfasf ', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=177&token=DYNAMIC', 177, 0, 0, 0, 0, '', NULL, '2025-12-05 05:05:04', '2025-12-05 05:40:57'),
(27, 6, ' asfdasfasdf as', ' asdf asfasf ', 'video', NULL, NULL, 'secure_preview_simple.php?file_id=177&token=DYNAMIC&file_name=dos.mp4&file_type=video', 177, 0, 0, 0, 0, '', NULL, '2025-12-05 05:40:50', '2025-12-05 05:41:00'),
(28, 6, 'ads fadfasdf', ' saasf asfd', 'video', NULL, NULL, 'secure_preview_simple.php?file_id=195&token=DYNAMIC&file_name=anonymous.mp4&file_type=video', 195, 0, 0, 0, 0, '', NULL, '2025-12-05 05:41:14', '2025-12-05 05:57:08'),
(29, 6, 'ads fadfasdf', ' saasf asfd', 'video', NULL, NULL, 'secure_preview_simple.php?file_id=195&token=DYNAMIC&file_name=anonymous.mp4&file_type=video', 195, 0, 0, 0, 0, '', NULL, '2025-12-05 05:53:58', '2025-12-05 05:57:14'),
(30, 6, 'ads fadfasdf', ' saasf asfd', 'video', NULL, NULL, 'secure_preview_simple.php?file_id=195&token=DYNAMIC&file_name=anonymous.mp4&file_type=video', 195, 0, 0, 0, 0, '', NULL, '2025-12-05 05:56:00', '2025-12-05 05:57:11'),
(31, 6, ' asdfasdf c', ' dfs', 'video', NULL, NULL, '../uploads/lms/1/1764603368_692db5e845a56.mp4', 153, 0, 0, 0, 0, '', NULL, '2025-12-05 05:57:24', '2025-12-09 05:04:51'),
(79, 8, 'Introduction', 'test', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=146&token=eaabf95211615cad6a84648fb86d62b3', 146, 0, 0, 0, 0, '', NULL, '2025-12-12 05:20:38', '2025-12-12 05:24:06'),
(94, 14, 's adfasfdasfd asdf', 'asd fasfdsaf', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=188&token=be016314d04c84589f2544dca50c997c', 188, 0, 0, 0, 0, '', NULL, '2025-12-13 07:01:44', '2025-12-17 08:12:40'),
(95, 14, 'sdfas asDADA', 'D ASDASDFASFDASFASF', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=149&token=6ece83ab27f3c2314efd43db3b566fb2', 149, 0, 0, 0, 0, '', NULL, '2025-12-13 07:02:03', '2025-12-17 08:12:40'),
(96, 14, ' ASDFSAF ASD', 'FASDFASFDASFASFD', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=172&token=f15c4e91452653d81f6f363cbef4cd9e', 172, 0, 0, 0, 0, '', NULL, '2025-12-13 07:02:16', '2025-12-17 08:12:40'),
(97, 14, ' asdfasf asfd', 'asfdasfdasfasfd', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=191&token=2336c8b59a491db4d5cd862fa0444290', 191, 0, 0, 0, 0, '', NULL, '2025-12-13 07:17:43', '2025-12-17 08:12:40'),
(98, 14, 'asd fasdf sa', 'saf asfdasfd', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=195&token=bda5a83e38fc5199e5ce0d0f7bb35b27', 195, 0, 0, 0, 0, '', NULL, '2025-12-13 07:18:40', '2025-12-17 08:12:40'),
(99, 14, 'asd fasdf sa', 'saf asfdasfd', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=195&token=97b8917868e51ac06e42d0f152a8b9b1', 195, 0, 0, 0, 0, '', NULL, '2025-12-13 07:18:42', '2025-12-17 08:12:40'),
(100, 16, 'Welcome & Course Introduction', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=146&token=0d46073d9a5b4df959966664f34fdc3a', 146, 0, 0, 0, 0, '', NULL, '2025-12-17 08:21:29', '2025-12-18 12:57:35'),
(101, 18, ' CIA triad', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=147&token=ceda3466e48804137ea7d653e4e78944', 147, 0, 0, 0, 0, '', NULL, '2025-12-17 09:51:48', '2025-12-18 12:59:23'),
(102, 18, 'Penetration testing scope and purpose', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=148&token=5083770ad67ab129733dd1b25626c0d4', 148, 0, 0, 0, 0, '', NULL, '2025-12-17 09:54:54', '2025-12-18 12:59:23'),
(103, 18, 'Types of hackers and pentests', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=149&token=9002a5aa86adc5405fa4312a241309dc', 149, 0, 0, 0, 0, '', NULL, '2025-12-17 09:55:21', '2025-12-18 12:59:23'),
(104, 17, 'Pentesting methodology', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=152&token=3d2eef63afefe76a96f5ff9de7610c38', 152, 0, 0, 0, 0, '', NULL, '2025-12-17 09:57:42', '2025-12-18 13:03:14'),
(105, 17, 'NIST basics', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=150&token=a9b516fbe059bd9f8b6d3031942098ae', 150, 0, 0, 0, 0, '', NULL, '2025-12-17 09:58:10', '2025-12-18 13:03:14'),
(106, 17, 'OWASP: Top 10 overview, testing guide mindset', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=151&token=1e4abb64db8dbec3d0aa77f60770781c', 151, 0, 0, 0, 0, '', NULL, '2025-12-17 09:58:31', '2025-12-18 13:03:14'),
(108, 21, 'Nikto – Basic Web Scanner', '', 'video', NULL, NULL, 'https://cyberwarlab.com/lab/secure_preview_simple.php?file_id=154&token=927ca87a89a6aab7ad5fe6e9deb2368b&file_name=nikto.mp4&file_type=mp4#no-back-button', 154, 0, 0, 0, 0, '', NULL, '2025-12-17 10:06:01', '2025-12-17 10:19:59'),
(109, 21, 'OpenVAS – Vulnerability Scanning', '', 'video', NULL, NULL, 'https://cyberwarlab.com/lab/secure_preview_simple.php?file_id=155&token=f83909ffca9777b8f773e1a03a7700a5&file_name=openvas.mp4&file_type=mp4#no-back-button', 155, 0, 0, 0, 0, '', NULL, '2025-12-17 10:06:31', '2025-12-17 10:19:59'),
(110, 21, ' ZAP – Automated ', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=157&token=c5b4645200b1c3337cf23ad55d802851', 157, 0, 0, 0, 0, '', NULL, '2025-12-17 10:07:30', '2025-12-17 10:19:59'),
(111, 21, 'Nessus – Vulnerability Assessment Scanner', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=153&token=65b64045f9c894bec24e3e43063a879c', 153, 0, 0, 0, 0, '', NULL, '2025-12-17 10:08:45', '2025-12-17 10:19:59'),
(112, 21, 'Web Check – XYZ (Quick Web App Review)', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=156&token=a9b101236533767a68ae6fcbe8a595ea', 156, 0, 0, 0, 0, '', NULL, '2025-12-17 10:10:41', '2025-12-17 10:19:59'),
(113, 24, 'Web Check – XYZ (Quick Web App Review)', '', 'video', NULL, NULL, 'https://cyberwarlab.com/lab/secure_preview_simple.php?file_id=156&token=2948f77b455dd19e34f9f7c79f21239c&file_name=web+scan.mp4&file_type=mp4#no-back-button', 156, 0, 0, 0, 0, '', NULL, '2025-12-17 10:20:59', '2025-12-26 05:14:54'),
(114, 24, ' Nikto – Basic Web Scanner', '', 'video', NULL, NULL, 'https://cyberwarlab.com/lab/secure_preview_simple.php?file_id=154&token=30888388292d15de4d15e4c6bab825ef&file_name=nikto.mp4&file_type=mp4#no-back-button', 154, 0, 0, 0, 0, '', NULL, '2025-12-17 10:21:19', '2025-12-26 05:14:54'),
(115, 24, 'OpenVAS – Vulnerability Scanning', '', 'video', NULL, NULL, 'https://cyberwarlab.com/lab/secure_preview_simple.php?file_id=155&token=adfcb14ccf75fda8f522fd99a68529d3&file_name=openvas.mp4&file_type=mp4#no-back-button', 155, 0, 0, 0, 0, '', NULL, '2025-12-17 10:23:32', '2025-12-26 05:14:54'),
(116, 24, 'ZAP – Automated', '', 'video', NULL, NULL, 'https://cyberwarlab.com/lab/secure_preview_simple.php?file_id=157&token=07d9bf9793841bbf3b122f74557d1eff&file_name=zap.mp4&file_type=mp4#no-back-button', 157, 0, 0, 0, 0, '', NULL, '2025-12-17 10:25:27', '2025-12-26 05:14:54'),
(117, 24, 'Nessus – Vulnerability Assessment Scanner', '', 'video', NULL, NULL, 'https://cyberwarlab.com/lab/secure_preview_simple.php?file_id=175&token=7d1e2bbd18da4c623e884bc405dbf48f&file_name=authentication.mp4&file_type=mp4#no-back-button', 175, 0, 0, 0, 0, '', NULL, '2025-12-17 10:26:43', '2025-12-26 05:14:54'),
(126, 25, 'test', 'test', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=175&token=5733f310d0b5307d83ece6834ea8bbf2', 175, 0, 0, 0, 0, 'active', NULL, '2025-12-17 10:59:27', '2025-12-17 10:59:27'),
(127, 25, 'asdfasdf', 'as fasdfasdf', '', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=196&token=20ce4c92ab15a2e080b9f0e40ce99ddb', 196, 0, 0, 0, 0, 'active', NULL, '2025-12-17 11:14:54', '2025-12-17 11:14:54'),
(128, 25, 'adfasdf asdf ', 'asdf asdfas', '', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=196&token=ce2b619b2dda63323263ad1f9e35989c', 196, 0, 0, 0, 0, 'active', NULL, '2025-12-17 11:27:10', '2025-12-17 11:27:10'),
(129, 27, 'The Certified Ethical Hacker Associate Roadmap', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=146&token=2aed641d3ded1f379712fd30815651cb', 146, 0, 0, 0, 0, 'active', NULL, '2025-12-18 12:58:53', '2026-01-24 11:03:33'),
(130, 29, 'CIA Triad: Core Principles of Cybersecurity', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=147&token=493d426866e90d24180b20c51039245c', 147, 0, 0, 0, 0, 'active', NULL, '2025-12-18 13:00:46', '2026-01-24 11:09:32'),
(131, 29, 'Classification of Penetration Testing Types ', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=149&token=a44689ef75b555eccea64ec037c3e510', 149, 0, 3, 0, 0, 'active', NULL, '2025-12-18 13:01:37', '2026-01-24 11:11:18'),
(132, 29, 'Penetration Testing: Scope, Objectives, and Legal Boundaries', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=148&token=10cbbbfc3dbb86979960effa663a68dd', 148, 0, 2, 0, 0, 'active', NULL, '2025-12-18 13:02:37', '2026-01-24 11:10:46'),
(133, 30, 'OWASP Top 10: Threat Landscape and Testing Mindset', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=151&token=826e586238d53a8bcb55ca76114c7ef0', 151, 0, 2, 0, 0, 'active', NULL, '2025-12-18 13:57:25', '2026-01-24 11:15:30'),
(134, 30, 'NIST Cybersecurity Framework: Core Concepts and Functions', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=150&token=0851bbd255efe830124a392f1cb40f7d', 150, 0, 0, 0, 0, 'active', NULL, '2025-12-18 13:58:15', '2026-01-24 11:14:37'),
(135, 30, 'Penetration Testing Methodology Lifecycle ', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=152&token=e7c76c70894456409af3a20412857caf', 152, 0, 1, 0, 0, 'active', NULL, '2025-12-18 13:58:54', '2026-01-24 11:15:02'),
(137, 31, 'Subdomain Enumeration Techniques and Tools', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=167&token=4b3814e6bb040b7b43057b7e68fab065', 167, 0, 3, 0, 0, 'active', NULL, '2025-12-18 14:03:15', '2026-01-31 15:53:05'),
(138, 31, 'Directory and Resource Discovery Methods', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=168&token=f584500fd802f82bae87deb10c841405', 168, 0, 4, 0, 0, 'active', NULL, '2025-12-18 14:03:45', '2026-01-31 15:53:05'),
(139, 32, 'Burp suite Introduction ', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=169&token=6773b097a66dc36aa865f682a9d04a04', 169, 0, 0, 0, 0, 'active', NULL, '2025-12-18 14:05:34', '2025-12-18 14:05:34'),
(140, 32, 'Burp Suite 2', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=170&token=d416d8021da8eb3a7cc3384c656fa061', 170, 0, 0, 0, 0, 'active', NULL, '2025-12-18 14:06:00', '2025-12-18 14:06:00'),
(141, 32, 'Burp Suite 3', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=171&token=25363701d653a5470f7b635e2e1df988', 171, 0, 0, 0, 0, 'active', NULL, '2025-12-18 14:06:29', '2025-12-18 14:06:29'),
(142, 32, 'SSL/TLS & Certificate Checks for Web Security', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=172&token=a4709a2f6e044e1008c8e97124090e0e', 172, 0, 0, 0, 0, 'active', NULL, '2025-12-18 14:10:01', '2025-12-18 14:10:01'),
(143, 19, 'Authentication & Broken Login Controls ', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=175&token=b26105c8d41539517b8235e048318005', 175, 0, 0, 0, 0, 'active', NULL, '2025-12-18 14:11:16', '2025-12-18 14:11:16'),
(145, 19, 'Denial of Service (DoS) Attacks ', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=177&token=9c74e69454a8bb289d294b85da09d867', 177, 0, 1, 0, 0, 'active', NULL, '2025-12-18 14:12:59', '2025-12-26 05:28:31'),
(147, 19, 'Command Injection Attacks', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=176&token=70cd8d7da20aaa3d8aa456e870e35f19', 176, 0, 3, 0, 0, 'active', NULL, '2025-12-18 14:14:20', '2025-12-26 05:28:31'),
(148, 19, 'Insecure File Upload Vulnerabilities ', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=178&token=0013e7e951b741ffbda5514062a743f8', 178, 0, 4, 0, 0, 'active', NULL, '2025-12-18 14:14:54', '2025-12-26 05:28:31'),
(149, 19, 'IDOR – Insecure Direct Object References', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=179&token=b15cff3999eca8d485e50530dc53addc', 179, 0, 5, 0, 0, 'active', NULL, '2025-12-18 14:15:21', '2025-12-26 05:28:31'),
(151, 19, 'Cross‑Site Scripting (XSS) Attacks', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=182&token=9b0f9d1a796521d593740502eb0fc3de', 182, 0, 6, 0, 0, 'active', NULL, '2025-12-18 14:24:19', '2025-12-26 05:28:31'),
(152, 19, 'Phishing Attack', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=180&token=b6fe5e64b3095e591fae9db65f7eea37', 180, 0, 7, 0, 0, 'active', NULL, '2025-12-18 14:25:50', '2025-12-26 05:28:31'),
(153, 33, 'IP Reputation Profiling with IPVoid', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=183&token=c44b40faed5dfff707b1a4834516c209', 183, 0, 0, 0, 0, 'active', NULL, '2025-12-18 14:28:37', '2026-01-31 16:01:46'),
(154, 33, 'OS Identification through Passive Network Fingerprinting', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=184&token=4cdded05db8bcefd3da2800933a1366a', 184, 0, 0, 0, 0, 'active', NULL, '2025-12-18 14:29:06', '2026-01-31 16:02:25'),
(155, 33, 'Shodan for Internet-Wide Device Intelligence', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=185&token=9708cf97d791767b4aa81a9a3ecfc796', 185, 0, 0, 0, 0, 'active', NULL, '2025-12-18 14:29:36', '2026-01-31 16:02:54'),
(156, 33, 'Network Traffic Collection with Tcpdump', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=186&token=45ab4981ce943f133af0e020e6498e70', 186, 0, 0, 0, 0, 'active', NULL, '2025-12-18 14:30:14', '2026-01-31 16:03:28'),
(157, 33, 'Deep Packet Analysis and Traffic Forensics', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=187&token=7e1ca80ad555c2903a731a86ea6d2c26', 187, 0, 0, 0, 0, 'active', NULL, '2025-12-18 14:31:06', '2026-01-31 16:03:59'),
(158, 33, 'Public-Facing Service Enumeration and Port Visibility Checks', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=188&token=ae0e7bdd0aed02bb1722ae36186f8afc', 188, 0, 0, 0, 0, 'active', NULL, '2025-12-18 14:31:34', '2026-01-31 16:04:32'),
(159, 33, 'Global Asset Discovery using FOFA Intelligence Platform', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=173&token=239bb4ca269881e3c8df75359bf017d1', 173, 0, 0, 0, 0, 'active', NULL, '2025-12-18 14:34:20', '2026-01-31 16:05:00'),
(160, 33, 'Contact Enumeration and OSINT Profiling', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=174&token=ef7c98f84632022cb38d1bed4124edb1', 174, 0, 0, 0, 0, 'active', NULL, '2025-12-18 14:34:58', '2026-01-31 16:05:44'),
(161, 34, 'Angry IP Scanner', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=189&token=a5151fb07232c3c2089e5f75f8648afb', 189, 0, 0, 0, 0, 'active', NULL, '2025-12-18 15:53:51', '2025-12-18 15:53:51'),
(162, 34, 'Netdiscover', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=190&token=13ea191728d20c8592529dc35b5fe872', 190, 0, 0, 0, 0, 'active', NULL, '2025-12-18 15:54:20', '2025-12-18 15:54:20'),
(163, 34, 'Nmap Basics ', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=191&token=6b9bad0afe62974e3aa167c08bca8325', 191, 0, 0, 0, 0, 'active', NULL, '2025-12-18 16:34:59', '2025-12-18 16:34:59'),
(165, 34, 'Nmap Advanced', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=192&token=54fc1800e3db0544725a20201845be88', 192, 0, 0, 0, 0, 'active', NULL, '2025-12-18 16:45:01', '2025-12-18 16:45:01'),
(166, 34, 'Uniscan', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=193&token=81df687bad2520082c67b1c00dc5253f', 193, 0, 0, 0, 0, 'active', NULL, '2025-12-18 16:45:40', '2025-12-18 16:45:40'),
(167, 34, 'Zenmap GUI', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=194&token=725aedaeaefbdb163ed5dda55d1fa929', 194, 0, 0, 0, 0, 'active', NULL, '2025-12-18 16:46:21', '2025-12-18 16:46:21'),
(168, 35, 'SNOW', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=204&token=41fa96df05a9637d2c2d091b2b478fe5', 204, 0, 0, 0, 0, 'active', NULL, '2025-12-19 13:58:38', '2025-12-19 13:58:38'),
(169, 35, 'Steghide ', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=203&token=2a177221b7a01085f664818099f40a0e', 203, 0, 0, 0, 0, 'active', NULL, '2025-12-19 14:00:55', '2025-12-19 14:00:55'),
(170, 35, 'OpenStego', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=202&token=c5187e328207704a43d7e3f793691aa4', 202, 0, 0, 0, 0, 'active', NULL, '2025-12-19 14:01:53', '2025-12-19 14:01:53'),
(171, 36, 'IP spoofing', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=195&token=ef8bc910aebe5689a1330c1b788427ad', 195, 0, 0, 0, 0, 'active', NULL, '2025-12-19 14:03:43', '2025-12-19 14:03:43'),
(172, 36, 'MAC spoofing', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=201&token=bdedeca02976ec677bc3541927124b3b', 201, 0, 0, 0, 0, 'active', NULL, '2025-12-19 14:04:10', '2025-12-19 14:04:10'),
(173, 37, 'HaveIBeenPawned', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=200&token=4e88238301dfd6a6c7aae0f0d95a63c3', 200, 0, 0, 0, 0, 'active', NULL, '2025-12-19 14:20:15', '2025-12-19 14:20:15'),
(174, 37, 'DeHashed', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=199&token=98b40ff5642c17d661957e6f060b4f7a', 199, 0, 0, 0, 0, 'active', NULL, '2025-12-19 14:20:54', '2025-12-19 14:20:54'),
(175, 37, 'Exploring the Dark Web Safely', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=198&token=795c3a40d405a104b2e0a9eda7538d82', 198, 0, 0, 0, 0, 'active', NULL, '2025-12-19 14:21:56', '2025-12-19 14:21:56'),
(176, 29, 'CEHA Knowledge Checkpoint 1', '', 'document', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=205&token=43c9ceb82d08010da1bf4580f90cf410', 205, 0, 1, 0, 0, 'active', NULL, '2025-12-19 15:33:39', '2026-01-24 11:12:09'),
(177, 30, 'CEHA Knowledge Checkpoint 3', '', 'document', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=207&token=46b64c223cdc2a5c2f9e4d2c2bba89f0', 207, 0, 3, 0, 0, 'active', NULL, '2025-12-19 15:35:54', '2026-01-24 11:16:16'),
(178, 29, 'CEHA Knowledge Checkpoint 2', '', 'document', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=209&token=6ae832c025fcd8818e8fe5e3d37b1876', 209, 0, 4, 0, 0, 'active', NULL, '2025-12-19 15:38:09', '2026-01-24 11:11:54'),
(179, 24, 'QUIZ 4', '', 'document', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=208&token=31b0590855b7591f2edf97289b909bf2', 208, 0, 0, 0, 0, '', NULL, '2025-12-19 15:40:11', '2025-12-26 05:14:54'),
(181, 38, 'Web Check ', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=156&token=b15d1238e8171104890d33611c3e2ee5', 156, 0, 0, 0, 0, 'active', NULL, '2025-12-26 05:16:14', '2025-12-26 05:16:14'),
(182, 38, 'Nikto – Basic Web Scanner', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=154&token=d478a4d173307f983f2f5c9f1530aad1', 154, 0, 0, 0, 0, 'active', NULL, '2025-12-26 05:19:04', '2025-12-26 05:19:04'),
(183, 38, 'OpenVAS – Vulnerability Scanning', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=155&token=f979eaa229fbe5c4fc1b882218407de5', 155, 0, 0, 0, 0, 'active', NULL, '2025-12-26 05:19:32', '2025-12-26 05:19:32'),
(184, 38, 'ZAP ', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=157&token=f0bb6d5256b8dfca1f6da67f3a57ad17', 157, 0, 0, 0, 0, 'active', NULL, '2025-12-26 05:19:56', '2025-12-26 05:19:56'),
(187, 38, 'Nessus', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=153&token=d45ae246da7aa65baecca78800431322', 153, 0, 0, 0, 0, 'active', NULL, '2025-12-26 05:24:54', '2025-12-26 05:24:54'),
(189, 19, 'SQL injection', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=181&token=d8a8d241ae3b2b1bacd1dd399612477c', 181, 0, 2, 0, 0, 'active', NULL, '2025-12-26 05:28:06', '2025-12-26 05:28:31'),
(190, 31, 'Google Dorking for OSINT and Security Research', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=210&token=be27c0651143bbaef7ad4cf9c5eb0c7b', 210, 0, 1, 0, 0, 'active', NULL, '2026-01-23 13:17:23', '2026-01-31 15:53:07'),
(191, 31, 'Introduction to Information Gathering and Reconnaissance Concepts', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=211&token=a9cf75944aacbbf62371d3cdbe3fda89', 211, 0, 0, 0, 0, 'active', NULL, '2026-01-23 13:18:19', '2026-01-31 15:50:59'),
(192, 19, 'Maxphisher', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=212&token=0ea51db7727f1976b6d7d2f37b1361b9', 212, 0, 0, 0, 0, 'active', NULL, '2026-01-23 13:19:17', '2026-01-23 13:19:17'),
(193, 19, 'How to access someone camera', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=213&token=ec437c109ef50197dd4f848b912cb708', 213, 0, 0, 0, 0, 'active', NULL, '2026-01-23 13:48:39', '2026-01-23 13:48:39'),
(194, 31, 'DNS Enumeration and Domain Intelligence Gathering', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=221&token=e1d7506cc2be2a45429a2a6640ce540d', 221, 0, 2, 0, 0, 'active', NULL, '2026-01-31 15:52:01', '2026-01-31 15:56:21'),
(195, 31, 'Web Technology Profiling and Historical Reconnaissance', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=222&token=0d3e9aca6e6e734837ae32d2deb57639', 222, 0, 0, 0, 0, 'active', NULL, '2026-01-31 15:55:43', '2026-01-31 15:55:43'),
(196, 31, 'Open-Source Intelligence Collection with theHarvester', '', 'video', NULL, NULL, '../public_html/LMS/preview_enhanced.php?file_id=220&token=b04c2429ad4f476eea19a0fa74fa6095', 220, 0, 0, 0, 0, 'active', NULL, '2026-01-31 15:56:56', '2026-01-31 15:59:21');

-- --------------------------------------------------------

--
-- Table structure for table `academy_lms_files`
--

CREATE TABLE `academy_lms_files` (
  `id` int(11) NOT NULL,
  `file_name` varchar(500) NOT NULL,
  `file_path` varchar(1000) NOT NULL,
  `file_type` varchar(50) NOT NULL,
  `file_size` bigint(20) DEFAULT 0,
  `source` enum('upload','lab_folder','lms_existing') DEFAULT 'upload',
  `original_path` varchar(1000) DEFAULT NULL,
  `uploaded_by` int(11) DEFAULT NULL,
  `upload_date` timestamp NOT NULL DEFAULT current_timestamp(),
  `last_accessed` timestamp NULL DEFAULT NULL,
  `access_count` int(11) DEFAULT 0,
  `status` enum('active','inactive','archived') DEFAULT 'active',
  `security_level` enum('public','course','private') DEFAULT 'course',
  `metadata` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`metadata`))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `academy_purchased_courses`
--

CREATE TABLE `academy_purchased_courses` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `course_id` int(11) DEFAULT NULL,
  `exam_package_id` int(11) DEFAULT NULL,
  `source` enum('academy','exam_package','migration') DEFAULT 'academy',
  `purchase_date` timestamp NOT NULL DEFAULT current_timestamp(),
  `amount` decimal(10,2) DEFAULT 0.00,
  `currency` varchar(3) DEFAULT 'INR',
  `payment_method` varchar(50) DEFAULT NULL,
  `transaction_id` varchar(100) DEFAULT NULL,
  `status` enum('active','expired','refunded','pending') DEFAULT 'active',
  `progress` int(11) DEFAULT 0,
  `completed_lessons` int(11) DEFAULT 0,
  `total_lessons` int(11) DEFAULT 0,
  `time_spent` int(11) DEFAULT 0,
  `last_accessed` timestamp NULL DEFAULT NULL,
  `certificate_issued` tinyint(1) DEFAULT 0,
  `certificate_number` varchar(100) DEFAULT NULL,
  `certificate_url` varchar(500) DEFAULT NULL,
  `issued_at` timestamp NULL DEFAULT NULL,
  `expires_at` timestamp NULL DEFAULT NULL,
  `completion_date` timestamp NULL DEFAULT NULL,
  `access_granted_ip` varchar(45) DEFAULT NULL,
  `notes` text DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `academy_ratings`
--

CREATE TABLE `academy_ratings` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `content_id` int(11) NOT NULL,
  `rating` tinyint(1) NOT NULL COMMENT '1-5 stars',
  `review` text DEFAULT NULL,
  `status` enum('active','hidden') NOT NULL DEFAULT 'active',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `academy_sections`
--

CREATE TABLE `academy_sections` (
  `id` int(11) NOT NULL,
  `title` varchar(255) NOT NULL,
  `description` text DEFAULT NULL,
  `access_required` varchar(50) DEFAULT NULL,
  `sort_order` int(11) NOT NULL DEFAULT 0,
  `status` enum('active','inactive') NOT NULL DEFAULT 'active',
  `created_by` int(11) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `academy_sections`
--

INSERT INTO `academy_sections` (`id`, `title`, `description`, `access_required`, `sort_order`, `status`, `created_by`, `created_at`, `updated_at`) VALUES
(1, 'Introduction to Ethical Hacking', 'Learn the fundamentals of ethical hacking and cybersecurity principles', NULL, 1, '', NULL, '2025-12-02 04:59:35', '2025-12-03 07:07:07'),
(2, 'Reconnaissance and Information Gathering', 'Master the art of passive and active reconnaissance techniques', NULL, 2, '', NULL, '2025-12-02 04:59:35', '2025-12-03 07:07:10'),
(3, 'Scanning and Enumeration', 'Discover vulnerabilities through network and application scanning', NULL, 3, '', NULL, '2025-12-02 04:59:35', '2025-12-03 07:07:12'),
(4, 'Exploitation Techniques', 'Learn various exploitation methods and post-exploitation activities', NULL, 4, '', NULL, '2025-12-02 04:59:35', '2025-12-03 07:07:14'),
(5, 'Web Application Security', 'Understand web vulnerabilities and security testing', NULL, 5, '', NULL, '2025-12-02 04:59:35', '2025-12-03 07:07:17'),
(6, '\n                                                Hero Section                                            ', '\n                                                Hii This is ddsdsd', 'CEHS', 1, '', NULL, '2025-12-03 07:27:17', '2025-12-12 05:24:04'),
(7, '\n                                                \n                                                \n                                                \n                                                \n                                                        He', '\n                                                \n                                                \n                                                i am testing this sectiod                                                                                                                                    ', 'CEHS', 0, '', NULL, '2025-12-10 06:28:34', '2025-12-12 05:17:34'),
(8, '\n                                                Introduction                                            ', '\n                                                test                                            ', 'CEHA', 0, '', NULL, '2025-12-12 05:18:05', '2025-12-12 05:24:06'),
(9, 'Introduction', '', '', 0, '', NULL, '2025-12-12 05:24:43', '2025-12-12 05:27:59'),
(10, 'Introduction', '', '', 0, '', NULL, '2025-12-12 05:27:02', '2025-12-12 05:27:56'),
(11, 'Introduction', '', '', 0, '', NULL, '2025-12-12 05:27:09', '2025-12-12 05:28:05'),
(12, 'Introduction', '', '', 0, '', NULL, '2025-12-12 05:27:14', '2025-12-12 05:28:02'),
(13, 'Introduction', '', 'CEHS', 0, '', NULL, '2025-12-12 05:27:33', '2025-12-12 05:28:07'),
(14, 'Introudction', '', 'CEHS', 0, '', NULL, '2025-12-12 05:28:47', '2025-12-17 08:12:40'),
(15, 'Admin Hacking', 'Hello ', 'CEHS', 1, '', NULL, '2025-12-12 05:29:35', '2025-12-17 08:12:43'),
(16, '\n                                                Introduction to Course', '', 'CEHA', 0, '', NULL, '2025-12-17 08:15:21', '2025-12-18 12:57:35'),
(17, 'Methodology & Frameworks (NIST, OWASP, etc.)', '', 'CEHA', 2, '', NULL, '2025-12-17 09:49:29', '2025-12-18 13:03:14'),
(18, ' Introduction to Pentesting', '', 'CEHA', 1, '', NULL, '2025-12-17 09:50:24', '2025-12-18 12:59:23'),
(19, 'Web Application Vulnerabilities & Exploitation                                                                                        ', '', 'CEHA', 10, 'active', NULL, '2025-12-17 10:02:43', '2026-01-31 15:45:24'),
(20, 'test Resources Uploading', 'test', 'CEHS', 1, '', NULL, '2025-12-17 10:04:09', '2025-12-17 10:05:37'),
(21, 'Automation & Manual Testing', '', 'CEHA', 4, '', NULL, '2025-12-17 10:04:45', '2025-12-17 10:19:59'),
(22, '\n                                                \n                                                test                                                                                        ', '\n                                                \n                                                test                                                                                        ', 'JRTO', 0, '', NULL, '2025-12-17 10:06:17', '2025-12-17 10:10:11'),
(23, 'test', 'test', 'JRTO', 1, '', NULL, '2025-12-17 10:10:21', '2025-12-17 10:28:39'),
(24, 'Automation Testing', '', 'CEHA', 3, '', NULL, '2025-12-17 10:20:18', '2025-12-26 05:14:54'),
(25, 'Test', 'test', 'CEHS', 0, 'active', NULL, '2025-12-17 10:29:01', '2025-12-17 10:29:01'),
(26, 'Test', 'test', 'CEHS', 0, '', NULL, '2025-12-17 10:33:05', '2025-12-17 10:33:20'),
(27, 'Welcome to CyberWarLab', '', 'CEHA', 0, 'active', NULL, '2025-12-18 12:57:56', '2026-01-24 11:02:02'),
(28, 'Cybersecurity basics', '', '', 0, 'active', NULL, '2025-12-18 12:59:52', '2025-12-18 12:59:52'),
(29, 'Core Cybersecurity Foundations                                            ', '', 'CEHA', 1, 'active', NULL, '2025-12-18 13:00:06', '2026-01-31 15:43:56'),
(30, 'Security Methodologies & Governance Frameworks                                            ', '', 'CEHA', 2, 'active', NULL, '2025-12-18 13:56:27', '2026-01-31 15:44:03'),
(31, 'Reconnaissance & Information Gathering                                            ', '', 'CEHA', 3, 'active', NULL, '2025-12-18 14:00:32', '2026-01-31 15:44:14'),
(32, 'Manual Web Application Security Testing                                            ', '', 'CEHA', 7, 'active', NULL, '2025-12-18 14:04:56', '2026-01-31 15:44:54'),
(33, 'Passive Reconnaissance & OSINT Intelligence                                            ', '', 'CEHA', 4, 'active', NULL, '2025-12-18 14:27:39', '2026-01-31 15:44:25'),
(34, 'Active Reconnaissance & Network Scanning                                            ', '', 'CEHA', 5, 'active', NULL, '2025-12-18 15:53:20', '2026-01-31 15:44:34'),
(35, 'Steganography & Covert Communication                                            ', '', 'CEHA', 11, 'active', NULL, '2025-12-19 13:48:12', '2026-01-31 15:45:32'),
(36, 'Anonymization & Identity Obfuscation                                            ', '', 'CEHA', 8, 'active', NULL, '2025-12-19 14:02:29', '2026-01-31 15:45:04'),
(37, 'Dark Web Intelligence & Breach Analysis\n                                            ', '', 'CEHA', 12, 'active', NULL, '2025-12-19 14:18:39', '2026-01-31 15:45:41'),
(38, 'Automated Vulnerability Assessment                                            ', '', 'CEHA', 6, 'active', NULL, '2025-12-26 05:15:09', '2026-01-31 15:44:45'),
(39, 'test', 'sdfasfdas fasf', 'CEHA', 0, '', NULL, '2026-01-15 05:11:14', '2026-01-15 05:11:27'),
(40, 'test', 'sdfasfdas fasf', 'CEHA', 0, '', NULL, '2026-01-15 05:11:21', '2026-01-15 05:11:39'),
(41, '\n                                                test sdfsadf d', '\n                                                sfds                                            ', 'CEHA', 0, '', NULL, '2026-01-15 05:12:08', '2026-01-15 05:12:38'),
(42, 'CEHA MODULE 9:Social Engineering Attacks & Human Exploitation', '', '', 9, 'active', NULL, '2026-01-24 11:25:46', '2026-01-24 11:25:46'),
(43, 'Social Engineering Attacks & Human Exploitation                                                                                        ', '', 'CEHA', 9, 'active', NULL, '2026-01-24 11:26:31', '2026-01-31 15:45:14');

-- --------------------------------------------------------

--
-- Table structure for table `academy_settings`
--

CREATE TABLE `academy_settings` (
  `id` int(11) NOT NULL,
  `setting_key` varchar(200) NOT NULL,
  `setting_value` longtext DEFAULT NULL,
  `setting_type` enum('string','number','boolean','json','array') DEFAULT 'string',
  `description` text DEFAULT NULL,
  `category` varchar(50) DEFAULT NULL,
  `is_public` tinyint(1) DEFAULT 0,
  `updated_by` int(11) DEFAULT NULL,
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `academy_settings`
--

INSERT INTO `academy_settings` (`id`, `setting_key`, `setting_value`, `setting_type`, `description`, `category`, `is_public`, `updated_by`, `updated_at`, `created_at`) VALUES
(1, 'academy_name', 'CyberWarLab Academy', 'string', 'Academy display name', 'general', 1, NULL, '2025-11-21 06:14:33', '2025-11-21 06:14:33'),
(2, 'academy_email', 'academy@cyberwarlab.com', 'string', 'Contact email', 'general', 1, NULL, '2025-11-21 06:14:33', '2025-11-21 06:14:33'),
(3, 'certificate_template', 'professional', 'string', 'Default certificate template', 'certificates', 0, NULL, '2025-11-21 06:14:33', '2025-11-21 06:14:33'),
(4, 'auto_certificate', 'true', 'boolean', 'Auto-generate certificates on completion', 'certificates', 0, NULL, '2025-11-21 06:14:33', '2025-11-21 06:14:33'),
(5, 'max_file_upload_size', '1024', 'number', 'Max file upload size in MB', 'uploads', 0, NULL, '2025-11-21 06:14:33', '2025-11-21 06:14:33'),
(6, 'secure_preview_enabled', 'true', 'boolean', 'Enable secure file preview', 'security', 0, NULL, '2025-11-21 06:14:33', '2025-11-21 06:14:33'),
(7, 'course_access_duration', '365', 'number', 'Course access duration in days', 'courses', 0, NULL, '2025-11-21 06:14:33', '2025-11-21 06:14:33'),
(8, 'enable_discussions', 'true', 'boolean', 'Enable course discussions', 'features', 0, NULL, '2025-11-21 06:14:33', '2025-11-21 06:14:33'),
(9, 'maintenance_mode', 'false', 'boolean', 'Put academy in maintenance mode', 'system', 0, NULL, '2025-11-21 06:14:33', '2025-11-21 06:14:33');

-- --------------------------------------------------------

--
-- Stand-in structure for view `academy_user_access_view`
-- (See below for the actual view)
--
CREATE TABLE `academy_user_access_view` (
`user_id` int(11)
,`username` varchar(50)
,`email` varchar(100)
,`access_status` varchar(7)
,`access_expires_at` timestamp /* mariadb-5.3 */
,`has_access` int(1)
);

-- --------------------------------------------------------

--
-- Table structure for table `academy_user_progress`
--

CREATE TABLE `academy_user_progress` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `content_id` int(11) NOT NULL,
  `completion_status` enum('not_started','in_progress','completed') NOT NULL DEFAULT 'not_started',
  `watch_time_seconds` int(11) NOT NULL DEFAULT 0,
  `completed_at` timestamp NULL DEFAULT NULL,
  `last_accessed` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `access_tokens`
--

CREATE TABLE `access_tokens` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `token` varchar(255) NOT NULL,
  `device_fingerprint` varchar(255) DEFAULT NULL,
  `expires_at` bigint(20) NOT NULL,
  `created_at` bigint(20) NOT NULL,
  `is_active` tinyint(1) DEFAULT 1
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `activity_logs`
--

CREATE TABLE `activity_logs` (
  `id` int(11) NOT NULL,
  `user_id` int(11) DEFAULT NULL,
  `action` varchar(100) NOT NULL,
  `details` text DEFAULT NULL,
  `entity_type` varchar(50) DEFAULT NULL,
  `entity_id` int(11) DEFAULT NULL,
  `course_id` int(11) DEFAULT NULL,
  `lesson_id` int(11) DEFAULT NULL,
  `duration` int(11) DEFAULT NULL,
  `metadata` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`metadata`)),
  `ip_address` varchar(45) DEFAULT NULL,
  `user_agent` text DEFAULT NULL,
  `session_id` varchar(100) DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `admin_credentials`
--

CREATE TABLE `admin_credentials` (
  `id` int(11) NOT NULL,
  `email` varchar(100) DEFAULT NULL,
  `password_hash` varchar(255) DEFAULT NULL,
  `status` enum('active','inactive') DEFAULT 'active',
  `created_at` timestamp NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `admin_credentials`
--

INSERT INTO `admin_credentials` (`id`, `email`, `password_hash`, `status`, `created_at`) VALUES
(1, 'admin1@cyberwarlab.com', '$2y$10$FqgL4mtpIbcaAqV6u4xBJOEYSj3CQ3gnky.adJTfKhD7EzCA80eT2', 'active', '2025-08-05 05:14:27');

-- --------------------------------------------------------

--
-- Table structure for table `admin_login_tokens`
--

CREATE TABLE `admin_login_tokens` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `token` varchar(255) NOT NULL,
  `token_type` enum('login','reset','api') DEFAULT 'login',
  `expires_at` timestamp NOT NULL,
  `used_at` timestamp NULL DEFAULT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `user_agent` text DEFAULT NULL,
  `is_active` tinyint(1) DEFAULT 1,
  `created_at` timestamp NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `admin_notifications`
--

CREATE TABLE `admin_notifications` (
  `id` int(11) NOT NULL,
  `type` varchar(50) NOT NULL,
  `title` varchar(200) NOT NULL,
  `message` text NOT NULL,
  `data` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`data`)),
  `status` enum('unread','read','dismissed') DEFAULT 'unread',
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `read_at` timestamp NULL DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `api_access_patterns`
--

CREATE TABLE `api_access_patterns` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `endpoint` varchar(255) NOT NULL,
  `method` varchar(10) NOT NULL,
  `ip_address` varchar(45) NOT NULL,
  `response_time_ms` int(11) DEFAULT 0,
  `status_code` int(11) NOT NULL,
  `request_size` int(11) DEFAULT 0,
  `response_size` int(11) DEFAULT 0,
  `anomaly_score` decimal(5,2) DEFAULT 0.00,
  `created_at` timestamp NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;

-- --------------------------------------------------------

--
-- Table structure for table `certificates`
--

CREATE TABLE `certificates` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `exam_session_id` int(11) NOT NULL,
  `package_id` int(11) NOT NULL,
  `certificate_number` varchar(50) NOT NULL,
  `certificate_title` varchar(200) NOT NULL,
  `issued_date` date NOT NULL,
  `expiry_date` date DEFAULT NULL,
  `score` decimal(5,2) DEFAULT NULL,
  `percentage` decimal(5,2) DEFAULT NULL,
  `grade` varchar(10) DEFAULT NULL,
  `certificate_path` varchar(255) DEFAULT NULL,
  `certificate_hash` varchar(255) DEFAULT NULL,
  `verification_code` varchar(100) DEFAULT NULL,
  `verification_url` varchar(255) DEFAULT NULL,
  `downloaded_count` int(11) DEFAULT 0,
  `last_downloaded` timestamp NULL DEFAULT NULL,
  `status` enum('active','revoked','expired') DEFAULT 'active',
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `certificate_audit_log`
--

CREATE TABLE `certificate_audit_log` (
  `id` int(11) NOT NULL,
  `certificate_id` varchar(100) NOT NULL,
  `admin_id` int(11) NOT NULL,
  `action` enum('created','updated','deleted','status_changed','regenerated') NOT NULL,
  `details` longtext DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `certificate_resources`
--

CREATE TABLE `certificate_resources` (
  `id` int(11) NOT NULL,
  `certificate_code` varchar(10) NOT NULL,
  `resource_name` varchar(255) NOT NULL,
  `resource_url` varchar(500) NOT NULL,
  `folder_id` int(11) DEFAULT NULL,
  `resource_type` enum('lab','tools','documentation','downloads','other') DEFAULT 'other',
  `description` text DEFAULT NULL,
  `sort_order` int(11) DEFAULT 0,
  `status` enum('active','inactive') DEFAULT 'active',
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `certificate_resources`
--

INSERT INTO `certificate_resources` (`id`, `certificate_code`, `resource_name`, `resource_url`, `folder_id`, `resource_type`, `description`, `sort_order`, `status`, `created_at`, `updated_at`) VALUES
(1, 'CEHA', 'CEHA Lab Environment', 'https://cyberwarlab.com/lab/folder_view.php?id=1', NULL, 'lab', 'Access your Certified Ethical Hacking Associate lab environment', 0, 'active', '2025-12-19 05:15:46', '2026-01-16 05:40:58'),
(2, 'CEHA', 'Kali Linux Download', 'https://www.kali.org/get-kali/', NULL, 'tools', 'Download Kali Linux for ethical hacking', 2, 'active', '2025-12-19 05:15:46', '2025-12-19 05:15:46'),
(3, 'CEHA', 'Metasploit Framework', 'https://www.metasploit.com/', NULL, 'tools', 'Access Metasploit penetration testing framework', 3, 'active', '2025-12-19 05:15:46', '2025-12-19 05:15:46'),
(4, 'CEHA', 'OWASP Top 10', 'https://owasp.org/www-project-top-ten/', NULL, 'documentation', 'OWASP Top 10 web application security risks', 4, 'active', '2025-12-19 05:15:46', '2025-12-19 05:15:46'),
(5, 'CEHS', 'Burp Suite', 'https://portswigger.net/burp', NULL, 'tools', 'Download Burp Suite for web application testing', 2, 'active', '2025-12-19 05:15:46', '2025-12-19 05:15:46'),
(6, 'CEHS', 'Nmap Official Guide', 'https://nmap.org/book/', NULL, 'documentation', 'Complete Nmap documentation', 3, 'active', '2025-12-19 05:15:46', '2025-12-19 05:15:46');

-- --------------------------------------------------------

--
-- Table structure for table `certificate_settings`
--

CREATE TABLE `certificate_settings` (
  `id` int(11) NOT NULL,
  `certificate_code` varchar(10) NOT NULL,
  `package_id` int(11) NOT NULL,
  `certificate_name` varchar(255) NOT NULL,
  `resources_enabled` tinyint(1) DEFAULT 0,
  `lab_folder_id` int(11) DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `certificate_settings`
--

INSERT INTO `certificate_settings` (`id`, `certificate_code`, `package_id`, `certificate_name`, `resources_enabled`, `lab_folder_id`, `created_at`, `updated_at`) VALUES
(1, 'CEHA', 1, 'Certified Ethical Hacking Associate', 1, 52, '2025-12-19 05:14:30', '2025-12-19 05:14:30'),
(2, 'CEHS', 2, 'Certified Ethical Hacking Specialist', 0, NULL, '2025-12-19 05:14:30', '2025-12-19 05:14:30'),
(3, 'JRTO', 3, 'Junior Red Team Operator', 0, NULL, '2025-12-19 05:14:30', '2025-12-19 05:14:30'),
(4, 'CRTS', 4, 'Certified Red Team Specialist', 0, NULL, '2025-12-19 05:14:30', '2025-12-19 05:14:30'),
(5, 'CRTM', 5, 'Certified Red Team Master', 0, NULL, '2025-12-19 05:14:30', '2025-12-19 05:14:30'),
(6, 'CDA', 6, 'Cyber Defense Analyst', 0, NULL, '2025-12-19 05:14:30', '2025-12-19 05:14:30'),
(7, 'BTOS', 7, 'Blue Team Operations Specialist', 0, NULL, '2025-12-19 05:14:30', '2025-12-19 05:14:30'),
(8, 'CDSP', 8, 'Certified Defensive Security Professional', 0, NULL, '2025-12-19 05:14:30', '2025-12-19 05:14:30');

-- --------------------------------------------------------

--
-- Table structure for table `certificate_validation_cache`
--

CREATE TABLE `certificate_validation_cache` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `certificate_code` varchar(20) NOT NULL,
  `is_valid` tinyint(1) NOT NULL,
  `validated_at` timestamp NULL DEFAULT current_timestamp(),
  `expires_at` timestamp NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;

-- --------------------------------------------------------

--
-- Table structure for table `cleanup_log_settings`
--

CREATE TABLE `cleanup_log_settings` (
  `id` int(11) NOT NULL,
  `setting_name` varchar(100) NOT NULL,
  `setting_value` text NOT NULL,
  `description` text DEFAULT NULL,
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `cleanup_log_settings`
--

INSERT INTO `cleanup_log_settings` (`id`, `setting_name`, `setting_value`, `description`, `updated_at`) VALUES
(1, 'auto_cleanup_enabled', '0', 'Enable/disable automatic log cleanup', '2025-11-21 09:24:12'),
(2, 'cleanup_interval_days', '7', 'Number of days after which logs are deleted', '2025-11-21 09:19:46'),
(3, 'last_cleanup_date', '2025-11-21 09:19:52', 'Date of last automatic cleanup', '2025-11-21 09:19:52'),
(4, 'cleanup_notification_enabled', '1', 'Send notification after automatic cleanup', '2025-11-21 09:19:46'),
(5, 'cleanup_admin_email', 'cyberwarlab1@gmail.com', 'Admin email for cleanup notifications', '2025-11-21 09:19:46'),
(11, '7', 'cleanup_interval_days', 'Number of days after which logs are deleted', '2025-11-21 09:30:19'),
(12, '1', 'auto_cleanup_enabled', 'Enable/disable automatic log cleanup', '2025-11-21 09:30:19'),
(13, '2025-11-28 09:30:19', 'last_cleanup_date', 'Date of last automatic cleanup', '2025-11-21 09:30:19'),
(16, '2025-11-28 09:30:32', 'last_cleanup_date', 'Date of last automatic cleanup', '2025-11-21 09:30:32');

-- --------------------------------------------------------

--
-- Table structure for table `comment_likes`
--

CREATE TABLE `comment_likes` (
  `id` int(11) NOT NULL,
  `comment_id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `like_type` enum('like','dislike') NOT NULL DEFAULT 'like',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `completion_tokens`
--

CREATE TABLE `completion_tokens` (
  `id` int(11) NOT NULL,
  `token` varchar(64) NOT NULL,
  `user_id` int(11) NOT NULL,
  `content_id` int(11) NOT NULL,
  `package_id` int(11) NOT NULL,
  `generated_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `expires_at` timestamp NOT NULL DEFAULT (current_timestamp() + interval 1 hour),
  `is_used` tinyint(1) NOT NULL DEFAULT 0,
  `used_at` timestamp NULL DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `contact_messages`
--

CREATE TABLE `contact_messages` (
  `id` int(11) NOT NULL,
  `name` varchar(100) NOT NULL,
  `email` varchar(100) NOT NULL,
  `phone` varchar(20) DEFAULT NULL,
  `subject` varchar(200) NOT NULL,
  `message` text NOT NULL,
  `service_type` varchar(50) DEFAULT NULL,
  `priority` enum('low','medium','high','urgent') DEFAULT 'medium',
  `source` varchar(50) DEFAULT 'website',
  `ip_address` varchar(45) DEFAULT NULL,
  `user_agent` text DEFAULT NULL,
  `status` enum('new','read','in_progress','replied','closed','spam') DEFAULT 'new',
  `assigned_to` int(11) DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `replied_at` timestamp NULL DEFAULT NULL,
  `replied_by` int(11) DEFAULT NULL,
  `internal_notes` text DEFAULT NULL,
  `client_access_key` varchar(32) DEFAULT NULL,
  `client_notified` tinyint(1) DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `contact_messages`
--

INSERT INTO `contact_messages` (`id`, `name`, `email`, `phone`, `subject`, `message`, `service_type`, `priority`, `source`, `ip_address`, `user_agent`, `status`, `assigned_to`, `created_at`, `replied_at`, `replied_by`, `internal_notes`, `client_access_key`, `client_notified`) VALUES
(90911, 'NAVEEN PAL', 'NAVEEN.KUMARPAL@OWASP.ORG', '+91 93117 81975', 'Strategic Sponsorship Invitation – CyberWarLab at CSA XCON 2026', 'Dear CyberWarLab Team,\r\n\r\nGreetings from CSA Dehradun Chapter.\r\n\r\nWe are pleased to formally invite CyberWarLab to partner with us as a Strategic Sponsor for CSA XCON 2026, an upcoming cybersecurity and cloud security conference bringing together industry leaders, researchers, CISOs, SOC heads, DFIR specialists, and governance professionals from across North India.\r\n\r\nCSA XCON 2026 will focus on:\r\n\r\n• Cloud Security & AI Governance\r\n• SOC & DFIR Operations\r\n• Emerging Threat Intelligence\r\n• Compliance, Risk & Regulatory Frameworks\r\n• Responsible AI & Secure AI Adoption\r\n\r\nGiven CyberWarLab’s expertise in offensive security, adversary simulation, cyber range exercises, and advanced threat research, your participation would add significant practical depth and real-world perspective to the conference discussions.\r\n\r\nProposed sponsorship benefits include:\r\n\r\n• Premium brand visibility across the conference website, digital campaigns, and stage branding\r\n• Opportunity for a keynote or featured technical session (e.g., Red Teaming, Adversary Tactics, or AI in Offensive Security)\r\n• Exhibition/demo space to showcase training platforms, cyber range capabilities, or research initiatives\r\n• Direct engagement with CISOs, SOC leaders, and enterprise security decision-makers\r\n• Recognition as a Strategic Cyber Defense Partner of CSA XCON 2026\r\n\r\nWe believe this collaboration would create strong technical visibility and meaningful engagement within the regional cybersecurity ecosystem.\r\n\r\nI would be happy to share our detailed sponsorship deck outlining available partnership tiers and benefits at your convenience.\r\n\r\nLooking forward to exploring this collaboration.\r\n\r\nWarm regards,\r\nNaveen\r\nCSA Dehradun Chapter\r\nhttps://csaxcon.com/', 'other', 'medium', 'website', '2a09:bac1:3680:68::2a8:38', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36', 'new', NULL, '2026-02-12 19:33:52', NULL, NULL, NULL, NULL, 0),
(90912, 'Jo Riggs', 'joriggsvideo@gmail.com', '', 'Video Promotion for cyberwarlab.com', 'Hi,\r\n\r\nI just visited cyberwarlab.com and wondered if you\'d ever thought about having an engaging video to explain what you do, or to be used on social media as a promotional tool?\r\n\r\nOur prices start from just $195 USD.\r\n\r\nLet me know if you\'re interested in seeing samples of our previous work.\r\n\r\nRegards,\r\nJo\n\nCertificate Program Interest: crtm', '', 'medium', 'website', '196.245.229.181', 'Mozilla/5.0 (X11; Linux i686; rv:114.0) Gecko/20100101 Firefox/114.0', 'new', NULL, '2026-02-13 03:01:51', NULL, NULL, NULL, NULL, 0),
(90913, 'Mike Erik Weber', 'info@strictlydigital.net', '89358286257', 'Semrush links for cyberwarlab.com', 'Hello, \r\n \r\nHaving some collection of links linking to cyberwarlab.com could have 0 value or harmful results for your business. \r\n \r\nIt really isn’t important how many inbound links you have, what matters is the amount of ranking terms those domains appear in search for. \r\n \r\nThat is the key element. \r\nNot the overrated Moz DA or Domain Rating. \r\nThese can be faked easily. \r\nBUT the amount of Google-ranked terms the websites that point to your site rank for. \r\nThat’s the bottom line. \r\n \r\nGet these quality links redirect to your site and your site will see real growth! \r\n \r\nWe are providing this powerful offer here: \r\nhttps://www.strictlydigital.net/product/semrush-backlinks/ \r\n \r\nHave questions, or need more information, chat with us here: \r\nhttps://www.strictlydigital.net/whatsapp-us/ \r\n \r\nKind regards, \r\nMike Erik Weber\r\n \r\nstrictlydigital.net \r\nPhone/WhatsApp: +1 (877) 566-3738\n\nCertificate Program Interest: cda', 'training', 'medium', 'website', '78.138.99.185', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36', 'new', NULL, '2026-02-13 12:24:26', NULL, NULL, NULL, NULL, 0),
(90914, 'Hi http://cyberwarlab.com/fekal0911 Webmaster', 'innarusha1105@gmail.com', '749942272', 'Hi http://cyberwarlab.com/fekal0911 Owner', 'Dear http://cyberwarlab.com/fekal0911 Owner\n\nCertificate Program Interest: btos', 'mobile_testing', 'medium', 'website', '144.124.230.83', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36', 'new', NULL, '2026-02-13 22:18:00', NULL, NULL, NULL, NULL, 0),
(90915, 'Saffet Erdogan', 'saffete141@gmail.com', '89691463424', 'Proposal for Fund Management Partnership', 'Dear Sir/Madam of the company. \r\n \r\nI hope this message finds you well. \r\n \r\nI am reaching out to you regarding a situation I am currently facing in Turkey. I am a businessman based in Istanbul, where I own textile and chemical manufacturing companies. I live here with my wife and son. \r\n \r\nDue to political circumstances, I am being pursued by the Turkish government. I will share full details once I hear back from you. In the meantime, I wish to entrust my funds, currently secured in Oman, to a reliable partner for management. \r\n \r\nThe total amount is USD 560,000,000 (Five Hundred and Sixty Million Dollars). My intention is to transfer these funds to you for safekeeping and management. As compensation, I am offering you a 5% management fee, which amounts to USD 28,000,000. This fee will be fully retained by you without any obligation for refund or future claims. \r\n \r\nThe remaining USD 532,000,000 will be returned to me after a period of ten years. There will be no interest, profit share, or additional compensation expected on this investment capital. \r\n \r\nOnce you confirm your interest. i will share more details , we will proceed with a full identification process and sign a formal fund management contract outlining these terms. After the contract is signed, the funds will be released to you by the security vault in Oman where they are currently held. You may receive the funds either through a bank transfer or via secure cash delivery, arranged with the financial institution in Oman. \r\n \r\nI look forward to your reply. Please contact me directly at: erdogansaffet2@gmail.com ). \r\n \r\nKind regards, \r\n \r\nSaffet Erdogan \r\nIstanbul, Turkey\n\nCertificate Program Interest: jrto', 'mobile_testing', 'medium', 'website', '158.173.156.38', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Avast/131.0.0.0', 'new', NULL, '2026-02-20 12:34:43', NULL, NULL, NULL, NULL, 0),
(90916, 'Piao Yuanri', 'piao4yuanri@gmail.com', '88397792428', 'INVESTMENT OFFER', 'Dear Sir/Madam, \r\n \r\nI trust this message finds you well. \r\n \r\nMy name is Piao Yuanri, Deputy Chief Financial Officer at Fidelity Investment Group, Hong Kong. We specialize in providing structured finance and venture capital solutions to established businesses and high-potential startups across global markets. \r\n \r\nThrough our network of reputable institutional partners, we currently have dedicated capital available for scalable, well-structured, and return driven projects across North America, Europe, the Middle East, Asia, and Australia. \r\n \r\nShould you be seeking growth financing or strategic investment, I would welcome the opportunity to discuss your funding requirements in greater detail. Kindly direct all correspondence to piao@fidicgroups.com, as I will respond exclusively to emails sent to this address. \r\n \r\nI look forward to your response. \r\n \r\nYours sincerely, \r\nPiao Yuanri \r\nDeputy Chief Financial Officer \r\nFidelity Investment Group \r\npiao@fidicgroups.com\n\nCertificate Program Interest: jrto', 'training', 'medium', 'website', '181.214.206.15', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36', 'new', NULL, '2026-02-27 11:39:02', NULL, NULL, NULL, NULL, 0),
(90917, 'Aliyu Abdullahi Bacce', 'aliyubacceitas@gmail.com', '080222326550', 'hand on labs', 'Help to build my career and networking\n\nCertificate Program Interest: jrto', 'red_team_service', 'medium', 'website', '102.91.92.141', 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Mobile Safari/537.36', 'new', NULL, '2026-03-01 15:52:49', NULL, NULL, NULL, NULL, 0);

-- --------------------------------------------------------

--
-- Table structure for table `contact_message_replies`
--

CREATE TABLE `contact_message_replies` (
  `id` int(11) NOT NULL,
  `contact_message_id` int(11) NOT NULL,
  `sender_type` enum('admin','client') NOT NULL,
  `sender_name` varchar(100) NOT NULL,
  `sender_email` varchar(100) DEFAULT NULL,
  `message` text NOT NULL,
  `is_internal_note` tinyint(1) DEFAULT 0,
  `created_at` timestamp NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `content_comments`
--

CREATE TABLE `content_comments` (
  `id` int(11) NOT NULL,
  `content_id` int(11) NOT NULL,
  `package_id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `parent_id` int(11) DEFAULT NULL,
  `comment_text` text NOT NULL,
  `comment_type` enum('user','admin','instructor') NOT NULL DEFAULT 'user',
  `status` enum('pending','approved','rejected','hidden') NOT NULL DEFAULT 'approved',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `content_comments`
--

INSERT INTO `content_comments` (`id`, `content_id`, `package_id`, `user_id`, `parent_id`, `comment_text`, `comment_type`, `status`, `created_at`, `updated_at`) VALUES
(1, 65, 2, 27, NULL, 'sdafs adf', 'user', 'approved', '2025-12-09 11:06:47', '2025-12-09 11:06:47'),
(113, 95, 2, 27, NULL, 'DSF ASFSA FASDF ASDF', 'user', 'approved', '2025-12-13 07:03:24', '2025-12-13 07:03:24'),
(114, 95, 2, 27, NULL, 'sa asdfsaf asdf', 'user', 'approved', '2025-12-13 07:08:04', '2025-12-13 07:08:04'),
(115, 96, 2, 27, NULL, 'asd fadsfs a', 'user', 'approved', '2025-12-13 07:08:14', '2025-12-13 07:08:14'),
(116, 95, 2, 27, NULL, 'asf dasfdf', 'user', 'approved', '2025-12-13 07:09:41', '2025-12-13 07:09:41'),
(117, 95, 2, 27, NULL, 'asf dasfdf', 'user', 'approved', '2025-12-13 07:09:41', '2025-12-13 07:09:41'),
(118, 94, 2, 27, NULL, 'as dfasdf asdsaf', 'user', 'approved', '2025-12-13 07:09:51', '2025-12-13 07:09:51'),
(119, 95, 2, 27, NULL, 'a sdfasdf asd', 'user', 'approved', '2025-12-13 07:10:37', '2025-12-13 07:10:37'),
(120, 97, 2, 27, NULL, 'asdfas fsaf s', 'user', 'approved', '2025-12-13 07:19:07', '2025-12-13 07:19:07'),
(121, 97, 2, 27, NULL, 'asdfasd asf ssa', 'user', 'approved', '2025-12-13 07:19:17', '2025-12-13 07:19:17'),
(122, 99, 2, 27, NULL, 'dfs saf', 'user', 'approved', '2025-12-13 07:19:29', '2025-12-13 07:19:29'),
(123, 98, 2, 27, NULL, 'd saasdf sadfsa ff', 'user', 'approved', '2025-12-13 07:28:47', '2025-12-13 07:28:47'),
(124, 97, 2, 27, NULL, 'sa dfasdf sadf', 'user', 'approved', '2025-12-13 07:28:49', '2025-12-13 07:28:49'),
(125, 97, 2, 27, NULL, 'Hw', 'user', 'approved', '2025-12-13 07:33:34', '2025-12-13 07:33:34'),
(126, 97, 2, 27, NULL, 'Hw', 'user', 'approved', '2025-12-13 07:33:45', '2025-12-13 07:33:45'),
(127, 95, 2, 27, NULL, 'Best', 'user', 'approved', '2025-12-13 07:37:32', '2025-12-13 07:37:32'),
(128, 0, 2, 21, NULL, 'hello', 'user', 'approved', '2025-12-16 18:44:33', '2025-12-16 18:44:33'),
(129, 95, 2, 27, NULL, 'asdfas fadsf', 'user', 'approved', '2025-12-17 06:17:36', '2025-12-17 06:17:36'),
(130, 95, 2, 27, NULL, 'asdf asdfa', 'user', 'approved', '2025-12-17 06:42:17', '2025-12-17 06:42:17'),
(131, 95, 2, 27, NULL, 'as df', 'user', 'approved', '2025-12-17 06:42:48', '2025-12-17 06:42:48'),
(132, 95, 2, 27, NULL, 'as df', 'user', 'approved', '2025-12-17 06:43:11', '2025-12-17 06:43:11'),
(133, 99, 2, 27, NULL, 'adfasdf', 'user', 'approved', '2025-12-17 06:43:21', '2025-12-17 06:43:21'),
(134, 0, 2, 27, NULL, 'asd fasfd', 'user', 'approved', '2025-12-17 06:48:38', '2025-12-17 06:48:38'),
(135, 0, 2, 27, NULL, 'asdf sadf', 'user', 'approved', '2025-12-17 06:48:43', '2025-12-17 06:48:43'),
(136, 95, 2, 27, NULL, 'ttttttttttttttttt', 'user', 'approved', '2025-12-17 06:49:05', '2025-12-17 06:49:05'),
(137, 99, 2, 27, NULL, 'sdfsfsafasfd safdasdfasfasf', 'user', 'approved', '2025-12-17 06:49:22', '2025-12-17 06:49:22'),
(138, 99, 2, 27, NULL, 'sdfsa fdasfd', 'user', 'approved', '2025-12-17 06:52:58', '2025-12-17 06:52:58'),
(139, 96, 2, 27, NULL, 'fgd sgds', 'user', 'approved', '2025-12-17 06:54:57', '2025-12-17 06:54:57'),
(140, 99, 2, 27, NULL, 'sdf gdsfg', 'user', 'approved', '2025-12-17 06:55:03', '2025-12-17 06:55:03'),
(141, 98, 2, 27, NULL, 'asdf asf', 'user', 'approved', '2025-12-17 06:56:53', '2025-12-17 06:56:53'),
(142, 98, 2, 27, NULL, 'asdf asf', 'user', 'approved', '2025-12-17 06:57:09', '2025-12-17 06:57:09'),
(143, 0, 2, 27, NULL, 'Hii', 'user', 'approved', '2025-12-17 07:01:04', '2025-12-17 07:01:04'),
(144, 0, 2, 27, NULL, 'Tes', 'user', 'approved', '2025-12-17 07:01:14', '2025-12-17 07:01:14'),
(145, 94, 2, 27, NULL, 'Test', 'user', 'approved', '2025-12-17 07:01:27', '2025-12-17 07:01:27'),
(146, 99, 2, 27, NULL, 'Hii', 'user', 'approved', '2025-12-17 07:03:16', '2025-12-17 07:03:16'),
(147, 96, 2, 27, NULL, 'test', 'user', 'approved', '2025-12-17 08:04:14', '2025-12-17 08:04:14'),
(148, 0, 2, 27, NULL, 'sdfsfs', 'user', 'approved', '2025-12-17 10:20:15', '2025-12-17 10:20:15'),
(149, 0, 2, 27, NULL, 'test', 'user', 'approved', '2025-12-17 10:43:34', '2025-12-17 10:43:34'),
(152, 0, 2, 27, NULL, 'sdfs', 'user', 'approved', '2025-12-17 11:04:36', '2025-12-17 11:04:36'),
(153, 0, 2, 27, NULL, 'df asdfdf d', 'user', 'approved', '2025-12-17 11:04:44', '2025-12-17 11:04:44'),
(154, 0, 2, 27, NULL, 'd fdf', 'user', 'approved', '2025-12-17 11:04:47', '2025-12-17 11:04:47'),
(155, 126, 2, 27, NULL, 'sdfsdf', 'user', 'approved', '2025-12-17 11:05:01', '2025-12-17 11:05:01'),
(156, 0, 2, 27, NULL, 'test', 'user', 'approved', '2025-12-17 11:15:54', '2025-12-17 11:15:54'),
(157, 126, 2, 27, NULL, 'd', 'user', 'approved', '2025-12-17 11:16:20', '2025-12-17 11:16:20'),
(158, 0, 2, 27, NULL, 'sdf', 'user', 'approved', '2025-12-18 08:40:05', '2025-12-18 08:40:05'),
(159, 0, 2, 27, NULL, 'sdf', 'user', 'approved', '2025-12-18 08:40:11', '2025-12-18 08:40:11'),
(160, 0, 1, 27, NULL, 'Best Course From Others', 'user', 'approved', '2025-12-19 04:49:38', '2025-12-19 04:49:38'),
(161, 129, 1, 27, NULL, 'best course from others', 'user', 'approved', '2025-12-19 04:50:08', '2025-12-19 04:50:08'),
(162, 138, 1, 27, NULL, 'qqq', 'user', 'approved', '2025-12-20 03:56:49', '2025-12-20 03:56:49'),
(163, 134, 1, 52, NULL, 'Hello anyone here', 'user', 'approved', '2025-12-20 14:44:33', '2025-12-20 14:44:33'),
(164, 0, 1, 27, NULL, 'sfdasf s', 'user', 'approved', '2025-12-23 09:59:28', '2025-12-23 09:59:28'),
(165, 0, 1, 27, NULL, 'test', 'user', 'approved', '2025-12-23 09:59:49', '2025-12-23 09:59:49'),
(166, 132, 1, 27, NULL, 'tste', 'user', 'approved', '2025-12-23 10:00:11', '2025-12-23 10:00:11'),
(167, 137, 1, 27, NULL, 'Hii', 'user', 'approved', '2025-12-30 08:02:53', '2025-12-30 08:02:53');

-- --------------------------------------------------------

--
-- Table structure for table `coupons`
--

CREATE TABLE `coupons` (
  `id` int(11) NOT NULL,
  `code` varchar(50) NOT NULL,
  `name` varchar(100) NOT NULL,
  `description` text DEFAULT NULL,
  `type` enum('percentage','fixed') NOT NULL,
  `value` decimal(10,2) NOT NULL,
  `minimum_amount` decimal(10,2) DEFAULT 0.00,
  `maximum_discount` decimal(10,2) DEFAULT NULL,
  `usage_limit` int(11) DEFAULT NULL,
  `used_count` int(11) DEFAULT 0,
  `user_limit` int(11) DEFAULT 1,
  `valid_from` timestamp NULL DEFAULT NULL,
  `valid_until` timestamp NULL DEFAULT NULL,
  `applicable_packages` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`applicable_packages`)),
  `status` enum('active','inactive','expired') DEFAULT 'active',
  `created_by` int(11) DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `coupon_usage`
--

CREATE TABLE `coupon_usage` (
  `id` int(11) NOT NULL,
  `coupon_id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `purchase_id` int(11) NOT NULL,
  `discount_amount` decimal(10,2) NOT NULL,
  `used_at` timestamp NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `courses`
--

CREATE TABLE `courses` (
  `id` int(11) NOT NULL,
  `title` varchar(500) NOT NULL,
  `description` longtext DEFAULT NULL,
  `short_description` varchar(1000) DEFAULT NULL,
  `duration` varchar(100) DEFAULT NULL,
  `price` decimal(10,2) DEFAULT 0.00,
  `original_price` decimal(10,2) DEFAULT 0.00,
  `category` varchar(50) DEFAULT NULL,
  `level` enum('beginner','intermediate','advanced','expert') DEFAULT 'beginner',
  `status` enum('draft','published','archived') DEFAULT 'draft',
  `total_lessons` int(11) DEFAULT 0,
  `total_hours` decimal(5,2) DEFAULT 0.00,
  `thumbnail` varchar(500) DEFAULT NULL,
  `preview_video` varchar(500) DEFAULT NULL,
  `requirements` text DEFAULT NULL,
  `objectives` text DEFAULT NULL,
  `what_you_learn` text DEFAULT NULL,
  `target_audience` text DEFAULT NULL,
  `language` varchar(10) DEFAULT 'en',
  `rating` decimal(3,2) DEFAULT 0.00,
  `total_reviews` int(11) DEFAULT 0,
  `enrollments` int(11) DEFAULT 0,
  `certificate_available` tinyint(1) DEFAULT 1,
  `certificate_template` varchar(100) DEFAULT 'default',
  `featured` tinyint(1) DEFAULT 0,
  `sort_order` int(11) DEFAULT 0,
  `source_package_id` int(11) DEFAULT NULL,
  `created_by` int(11) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `published_at` timestamp NULL DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `course_lessons`
--

CREATE TABLE `course_lessons` (
  `id` int(11) NOT NULL,
  `section_id` int(11) NOT NULL,
  `title` varchar(255) NOT NULL,
  `description` text DEFAULT NULL,
  `duration` varchar(50) DEFAULT NULL,
  `video_url` varchar(500) DEFAULT NULL,
  `file_url` varchar(500) DEFAULT NULL,
  `file_type` varchar(20) DEFAULT NULL,
  `file_size` bigint(20) DEFAULT 0,
  `lms_file_id` int(11) DEFAULT NULL,
  `source_type` enum('upload','lab_folder','lms_existing') DEFAULT 'upload',
  `sort_order` int(11) DEFAULT 0,
  `status` enum('active','inactive') DEFAULT 'active',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `course_package_mapping`
--

CREATE TABLE `course_package_mapping` (
  `id` int(11) NOT NULL,
  `exam_package_id` int(11) NOT NULL,
  `academy_course_id` int(11) DEFAULT NULL,
  `title` varchar(500) DEFAULT NULL,
  `description` text DEFAULT NULL,
  `map_type` enum('upgrade','replace','integrate') DEFAULT 'integrate',
  `status` enum('pending','active','inactive') DEFAULT 'pending',
  `mapping_data` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`mapping_data`)),
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `course_sections`
--

CREATE TABLE `course_sections` (
  `id` int(11) NOT NULL,
  `course_id` int(11) NOT NULL,
  `title` varchar(255) NOT NULL,
  `description` text DEFAULT NULL,
  `sort_order` int(11) DEFAULT 0,
  `status` enum('active','inactive') DEFAULT 'active',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `device_fingerprints`
--

CREATE TABLE `device_fingerprints` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `fingerprint_hash` varchar(64) NOT NULL,
  `fingerprint_data` text DEFAULT NULL,
  `first_seen` timestamp NULL DEFAULT current_timestamp(),
  `last_seen` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `is_trusted` tinyint(1) DEFAULT 0,
  `suspicious_score` decimal(5,2) DEFAULT 0.00
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `discount_banners`
--

CREATE TABLE `discount_banners` (
  `id` int(11) NOT NULL,
  `banner_title` varchar(255) NOT NULL,
  `description` text DEFAULT NULL,
  `discount_percentage` decimal(5,2) NOT NULL DEFAULT 0.00,
  `theme` enum('winter','hot_days') DEFAULT 'winter',
  `promo_code` varchar(50) DEFAULT NULL,
  `start_date` datetime NOT NULL,
  `end_date` datetime NOT NULL,
  `is_active` tinyint(1) DEFAULT 1,
  `button_text` varchar(100) DEFAULT 'Get Discount',
  `button_link` varchar(500) DEFAULT '/exam/packages.php',
  `background_color` varchar(20) DEFAULT '#1e3a5f',
  `text_color` varchar(20) DEFAULT '#ffffff',
  `accent_color` varchar(20) DEFAULT '#ef4444',
  `show_countdown` tinyint(1) DEFAULT 1,
  `show_on_homepage` tinyint(1) DEFAULT 1,
  `show_on_dashboard` tinyint(1) DEFAULT 1,
  `display_order` int(11) DEFAULT 0,
  `created_by` int(11) DEFAULT NULL,
  `updated_by` int(11) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `discount_banners`
--

INSERT INTO `discount_banners` (`id`, `banner_title`, `description`, `discount_percentage`, `theme`, `promo_code`, `start_date`, `end_date`, `is_active`, `button_text`, `button_link`, `background_color`, `text_color`, `accent_color`, `show_countdown`, `show_on_homepage`, `show_on_dashboard`, `display_order`, `created_by`, `updated_by`, `created_at`, `updated_at`) VALUES
(5, 'test', NULL, 50.00, 'winter', '', '2026-02-11 05:54:00', '2026-02-28 01:06:00', 0, 'Get Discount', '/exam/packages.php', '#1e3a5f', '#ffffff', '#ef4444', 1, 1, 1, 0, 1, 1, '2026-02-12 05:28:37', '2026-02-12 05:35:01'),
(6, 'Cold Days', NULL, 30.00, 'winter', 'HAPPY100', '2026-02-12 05:05:00', '2026-02-26 05:00:00', 1, 'Get Discount', '/exam/packages.php', '#1e3a5f', '#ffffff', '#ef4444', 1, 1, 1, 0, 1, NULL, '2026-02-12 05:35:59', '2026-02-12 05:35:59');

-- --------------------------------------------------------

--
-- Table structure for table `email_otp_verifications`
--

CREATE TABLE `email_otp_verifications` (
  `id` int(11) NOT NULL,
  `email` varchar(255) NOT NULL,
  `otp_code` varchar(6) NOT NULL,
  `attempts_count` int(11) DEFAULT 0,
  `resend_count` int(11) DEFAULT 0,
  `is_verified` tinyint(1) DEFAULT 0,
  `expires_at` datetime NOT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `verified_at` datetime DEFAULT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `user_agent` text DEFAULT NULL,
  `session_token` varchar(255) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `email_otp_verifications`
--

INSERT INTO `email_otp_verifications` (`id`, `email`, `otp_code`, `attempts_count`, `resend_count`, `is_verified`, `expires_at`, `created_at`, `verified_at`, `ip_address`, `user_agent`, `session_token`) VALUES
(409, 'gavireddigowtham91962@gmail.com', 'U8S8IJ', 1, 0, 1, '2026-03-02 15:52:36', '2026-03-02 10:12:36', '2026-03-02 10:13:34', '2409:40c1:1005:2984:4084:58ff:fe3d:f177', 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Mobile Safari/537.36', NULL);

-- --------------------------------------------------------

--
-- Table structure for table `email_queue`
--

CREATE TABLE `email_queue` (
  `id` int(11) NOT NULL,
  `recipient_email` varchar(255) NOT NULL,
  `recipient_name` varchar(100) NOT NULL,
  `subject` varchar(255) NOT NULL,
  `body` text NOT NULL,
  `status` enum('pending','sent','failed','cancelled') DEFAULT 'pending',
  `attempts` int(11) DEFAULT 0,
  `last_attempt` timestamp NULL DEFAULT NULL,
  `error_message` text DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `sent_at` timestamp NULL DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `enhanced_security_events`
--

CREATE TABLE `enhanced_security_events` (
  `id` int(11) NOT NULL,
  `user_id` int(11) DEFAULT NULL,
  `event_type` enum('token_request','token_validate','download_success','download_blocked','nonce_reuse','invalid_signature','rate_limit_exceeded','origin_mismatch') NOT NULL,
  `file_id` int(11) DEFAULT NULL,
  `folder_id` int(11) DEFAULT NULL,
  `nonce` varchar(64) DEFAULT NULL,
  `token_hash` varchar(128) DEFAULT NULL,
  `ip_address` varchar(45) NOT NULL,
  `user_agent` text DEFAULT NULL,
  `origin` varchar(255) DEFAULT NULL,
  `referer` varchar(500) DEFAULT NULL,
  `response_time_ms` int(11) DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `exam_attempts`
--

CREATE TABLE `exam_attempts` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `package_id` int(11) NOT NULL,
  `session_id` int(11) NOT NULL,
  `attempt_number` int(11) DEFAULT 1,
  `score` int(11) DEFAULT 0,
  `percentage` decimal(5,2) DEFAULT 0.00,
  `passed` tinyint(1) DEFAULT 0,
  `time_spent` int(11) DEFAULT 0,
  `started_at` timestamp NULL DEFAULT NULL,
  `completed_at` timestamp NULL DEFAULT NULL,
  `status` enum('in_progress','completed','abandoned') DEFAULT 'in_progress',
  `answers_data` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`answers_data`)),
  `created_at` timestamp NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `exam_categories`
--

CREATE TABLE `exam_categories` (
  `id` int(11) NOT NULL,
  `category_name` varchar(100) NOT NULL,
  `category_slug` varchar(100) NOT NULL,
  `description` text DEFAULT NULL,
  `icon` varchar(50) DEFAULT NULL,
  `color` varchar(20) DEFAULT '#ff0000',
  `display_order` int(11) DEFAULT 0,
  `status` enum('active','inactive') DEFAULT 'active',
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `exam_categories`
--

INSERT INTO `exam_categories` (`id`, `category_name`, `category_slug`, `description`, `icon`, `color`, `display_order`, `status`, `created_at`, `updated_at`) VALUES
(1, 'Ethical Hacking', 'ethical-hacking', 'Comprehensive ethical hacking and penetration testing certification covering reconnaissance, vulnerability assessment, exploitation, and post-exploitation techniques.', 'fas fa-crosshairs', '#ff0000', 1, 'active', '2025-07-18 02:05:05', '2025-07-18 02:05:05'),
(2, 'Red Team Operations', 'red-team', 'Advanced red team tactics and adversary simulation including APT campaigns, social engineering, and sophisticated attack methodologies.', 'fas fa-skull', '#ff0000', 2, 'active', '2025-07-18 02:05:05', '2025-07-18 02:05:05'),
(3, 'Blue Team Defense', 'blue-team', 'Defensive cybersecurity and incident response including threat hunting, digital forensics, and security monitoring.', 'fas fa-shield-alt', '#0066ff', 3, 'active', '2025-07-18 02:05:05', '2025-07-18 02:05:05'),
(4, 'ICS/SCADA Security', 'ics-security', 'Industrial control systems security assessment covering SCADA, PLC, and critical infrastructure protection.', 'fas fa-industry', '#0066ff', 4, 'active', '2025-07-18 02:05:05', '2025-07-18 02:05:05'),
(5, 'Cryptography', 'cryptography', 'Advanced cryptographic analysis and implementation including symmetric/asymmetric encryption, hash functions, and PKI.', 'fas fa-lock', '#0066ff', 5, 'active', '2025-07-18 02:05:05', '2025-07-18 02:05:05'),
(6, 'Mobile Security', 'mobile-security', 'Mobile application security testing for Android and iOS platforms including reverse engineering and dynamic analysis.', 'fas fa-mobile-alt', '#00aa00', 6, 'active', '2025-07-18 02:05:05', '2025-07-18 02:05:05');

-- --------------------------------------------------------

--
-- Table structure for table `exam_packages`
--

CREATE TABLE `exam_packages` (
  `id` int(11) NOT NULL,
  `package_name` varchar(100) NOT NULL,
  `access_code` varchar(10) DEFAULT NULL,
  `category_id` int(11) DEFAULT NULL,
  `description` text DEFAULT NULL,
  `detailed_description` longtext DEFAULT NULL,
  `price` decimal(10,2) NOT NULL,
  `duration_minutes` int(11) NOT NULL,
  `total_questions` int(11) NOT NULL,
  `passing_score` int(11) NOT NULL,
  `certificate_template` varchar(255) DEFAULT NULL,
  `validity_days` int(11) DEFAULT 30,
  `max_attempts` int(11) DEFAULT 3,
  `features` longtext DEFAULT NULL CHECK (json_valid(`features`)),
  `prerequisites` text DEFAULT NULL,
  `difficulty_level` enum('beginner','intermediate','advanced','expert') DEFAULT 'intermediate',
  `is_featured` tinyint(1) DEFAULT 0,
  `status` enum('active','inactive','coming_soon') DEFAULT 'active',
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `exam_packages`
--

INSERT INTO `exam_packages` (`id`, `package_name`, `access_code`, `category_id`, `description`, `detailed_description`, `price`, `duration_minutes`, `total_questions`, `passing_score`, `certificate_template`, `validity_days`, `max_attempts`, `features`, `prerequisites`, `difficulty_level`, `is_featured`, `status`, `created_at`, `updated_at`) VALUES
(1, 'CEHA', 'CEHA', 1, 'Foundation-level ethical hacking and penetration testing certification', 'This entry-level certification validates your foundational skills in ethical hacking and penetration testing. Topics include reconnaissance, scanning, enumeration, vulnerability assessment, system hacking, malware threats, social engineering, denial of service, session hijacking, web application hacking, wireless network hacking, mobile security, and cryptography basics.', 4999.00, 240, 20, 75, NULL, 90, 2, '[\"24/7 Lab Access\", \"Hands-on Virtual Labs\", \"Real-world Scenarios\", \"Industry Recognition\", \"Career Support\"]', 'Basic computer networking knowledge', 'beginner', 1, 'active', '2025-07-18 02:05:05', '2026-02-02 13:21:50'),
(2, 'CEHS', 'CEHS', 1, 'Advanced ethical hacking and cybersecurity specialist certification', 'This advanced certification validates your expertise in ethical hacking, advanced penetration testing, and cybersecurity analysis. Topics include advanced vulnerability assessment, exploit development, post-exploitation techniques, advanced network security, cloud security, incident response, digital forensics, and security architecture design.', 5999.00, 360, 20, 75, NULL, 120, 2, '[\"Advanced Lab Environment\", \"Cloud Security Labs\", \"Exploit Development Kit\", \"Industry Mentorship\", \"Job Placement Support\", \"CEH Mapping\"]', 'Basic networking knowledge and CEHA certification recommended', 'advanced', 1, 'coming_soon', '2025-08-08 07:44:26', '2026-02-02 13:21:56'),
(3, 'JRTO', 'JRTO', 2, 'Entry-level red team operations and adversarial simulation', 'This certification introduces red team methodologies and adversarial simulation techniques. Topics include threat modeling, MITRE ATT&CK framework, initial access techniques, persistence mechanisms, privilege escalation, lateral movement, command and control, and basic evasion techniques.', 4999.00, 300, 120, 70, NULL, 90, 2, '[\"Red Team Simulation Labs\", \"MITRE ATT&CK Training\", \"Adversarial Tactics\", \"Team Collaboration Tools\", \"Industry Recognition\"]', 'Basic cybersecurity knowledge', 'beginner', 0, 'coming_soon', '2025-08-08 07:44:26', '2026-02-02 13:22:02'),
(4, 'CRTS', 'CRTS', 2, 'Advanced red team operations and campaign management', 'This advanced certification validates expertise in complex red team operations, campaign planning, and advanced adversarial simulation. Topics include advanced persistent threats (APT) simulation, custom payload development, advanced evasion techniques, social engineering campaigns, physical security assessments, and red team reporting.', 0.00, 540, 250, 85, NULL, 180, 2, '[\"Advanced Red Team Labs\", \"Custom Payload Development\", \"APT Simulation Environment\", \"Social Engineering Training\", \"Physical Security Labs\", \"Expert Mentorship\"]', 'JRTA certification or equivalent experience', 'expert', 1, 'coming_soon', '2025-08-08 07:44:26', '2025-12-05 04:43:14'),
(5, 'CRTM', 'CRTM', 3, 'Red team leadership, strategy, and program management', 'This executive-level certification focuses on red team program management, strategic planning, and leadership. Topics include red team program development, threat intelligence integration, risk assessment methodologies, stakeholder communication, team management, budget planning, and compliance frameworks.', 0.00, 420, 180, 80, NULL, 365, 2, '[\"Leadership Training Modules\", \"Strategic Planning Tools\", \"Team Management Resources\", \"Executive Reporting Templates\", \"Industry Networking\", \"Continuing Education Credits\"]', 'CRTS certification and management experience', 'expert', 1, 'coming_soon', '2025-08-08 07:44:26', '2025-12-05 04:43:14'),
(6, 'CDA', 'CDA', 4, 'Digital forensics and incident response specialist certification', 'This certification validates skills in digital forensics, incident response, and cyber threat analysis. Topics include digital evidence acquisition, forensic analysis techniques, malware analysis, network forensics, mobile device forensics, cloud forensics, incident response procedures, and expert witness testimony.', 0.00, 240, 20, 75, NULL, 120, 2, '[\"Digital Forensics Labs\", \"Malware Analysis Sandbox\", \"Mobile Forensics Tools\", \"Cloud Investigation Environment\", \"Legal Training Modules\", \"Expert Witness Preparation\"]', 'Basic IT knowledge and understanding of legal procedures', 'intermediate', 0, 'coming_soon', '2025-08-08 07:44:26', '2025-12-05 04:43:14'),
(7, 'BTOS', 'BTOS', 5, 'Defensive cybersecurity operations and threat hunting', 'This certification focuses on defensive cybersecurity operations, threat hunting, and security monitoring. Topics include security operations center (SOC) operations, threat hunting methodologies, security information and event management (SIEM), intrusion detection systems, incident response, threat intelligence analysis, and defensive countermeasures.', 0.00, 390, 160, 75, NULL, 90, 2, '[\"SOC Simulation Environment\", \"Threat Hunting Labs\", \"SIEM Training Platform\", \"Incident Response Scenarios\", \"Threat Intelligence Feeds\", \"Industry Certifications Mapping\"]', 'Network security fundamentals', 'intermediate', 1, 'coming_soon', '2025-08-08 07:44:26', '2025-12-05 04:43:14'),
(8, 'CDSP', 'CDSP', 6, 'DevSecOps implementation and secure software development', 'This certification validates expertise in DevSecOps practices, secure software development, and CI/CD security. Topics include secure coding practices, application security testing, container security, infrastructure as code security, CI/CD pipeline security, security automation, compliance as code, and security metrics and monitoring.', 0.00, 360, 140, 75, NULL, 120, 2, '[\"DevSecOps Lab Environment\", \"Container Security Training\", \"CI/CD Security Tools\", \"Secure Coding Workshops\", \"Automation Scripting Labs\", \"Cloud Native Security\"]', 'Software development experience and basic security knowledge', 'advanced', 1, 'coming_soon', '2025-08-08 07:44:26', '2025-12-05 04:43:14');

-- --------------------------------------------------------

--
-- Table structure for table `exam_questions`
--

CREATE TABLE `exam_questions` (
  `id` int(11) NOT NULL,
  `question` text NOT NULL,
  `option_a` varchar(255) NOT NULL,
  `option_b` varchar(255) NOT NULL,
  `option_c` varchar(255) NOT NULL,
  `option_d` varchar(255) NOT NULL,
  `correct_option` int(11) NOT NULL,
  `difficulty` enum('easy','medium','hard') DEFAULT 'medium',
  `created_at` timestamp NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `exam_questions`
--

INSERT INTO `exam_questions` (`id`, `question`, `option_a`, `option_b`, `option_c`, `option_d`, `correct_option`, `difficulty`, `created_at`) VALUES
(1, 'What is the most common vulnerability in web applications?', 'XSS', 'SQL Injection', 'CSRF', 'RCE', 1, 'medium', '2025-08-05 11:08:19'),
(2, 'Which tool is commonly used for network scanning?', 'Nmap', 'Wireshark', 'Burp Suite', 'Metasploit', 0, 'easy', '2025-08-05 11:08:19'),
(3, 'What does OWASP stand for?', 'Open Web Application Security Project', 'Online Web App Security Protocol', 'Open World Application Security Platform', 'Online Web Application Security Project', 0, 'easy', '2025-08-05 11:08:19'),
(4, 'Which of the following is a common SQL injection payload?', '\' OR \'1\'=\'1', '<script>alert(1)</script>', '../../etc/passwd', 'rm -rf /', 0, 'medium', '2025-08-05 11:08:19'),
(5, 'What port does SSH typically use?', '21', '22', '23', '80', 1, 'easy', '2025-08-05 11:08:19'),
(6, 'Which HTTP method is typically vulnerable to CSRF attacks?', 'GET', 'POST', 'PUT', 'DELETE', 1, 'medium', '2025-08-05 11:08:19'),
(7, 'What is the purpose of a WAF?', 'Web Application Firewall', 'Wireless Access Filter', 'Wide Area Framework', 'Web Authentication Factor', 0, 'medium', '2025-08-05 11:08:19'),
(8, 'Which tool is best for intercepting HTTP requests?', 'Nmap', 'Burp Suite', 'Wireshark', 'John the Ripper', 1, 'easy', '2025-08-05 11:08:19'),
(9, 'What does XSS stand for?', 'Cross-Site Scripting', 'eXternal Site Security', 'eXtended Security System', 'Cross-System Script', 0, 'easy', '2025-08-05 11:08:19'),
(10, 'Which of these is a password cracking tool?', 'Nmap', 'Wireshark', 'John the Ripper', 'Burp Suite', 2, 'easy', '2025-08-05 11:08:19'),
(11, 'What is the default port for HTTPS?', '80', '443', '8080', '8443', 1, 'easy', '2025-08-05 11:08:19'),
(12, 'Which vulnerability allows code execution on the server?', 'XSS', 'CSRF', 'RCE', 'SQLi', 2, 'hard', '2025-08-05 11:08:19'),
(13, 'What is a common method to prevent SQL injection?', 'Input validation', 'Prepared statements', 'Output encoding', 'Both A and B', 3, 'medium', '2025-08-05 11:08:19'),
(14, 'Which protocol is used for secure file transfer?', 'FTP', 'SFTP', 'HTTP', 'SMTP', 1, 'easy', '2025-08-05 11:08:19'),
(15, 'What does CSRF stand for?', 'Cross-Site Request Forgery', 'Client-Server Request Filter', 'Cross-System Resource Failure', 'Certified Security Request Format', 0, 'medium', '2025-08-05 11:08:19'),
(16, 'Which tool is used for network packet analysis?', 'Nmap', 'Metasploit', 'Wireshark', 'Burp Suite', 2, 'easy', '2025-08-05 11:08:19'),
(17, 'What is the purpose of penetration testing?', 'To break systems', 'To find vulnerabilities', 'To install malware', 'To steal data', 1, 'easy', '2025-08-05 11:08:19'),
(18, 'Which attack targets the application layer?', 'DDoS', 'Man-in-the-middle', 'SQL Injection', 'ARP Spoofing', 2, 'medium', '2025-08-05 11:08:19'),
(19, 'What is social engineering?', 'Code exploitation', 'Network scanning', 'Human manipulation', 'System administration', 2, 'medium', '2025-08-05 11:08:19');

-- --------------------------------------------------------

--
-- Table structure for table `exam_results`
--

CREATE TABLE `exam_results` (
  `id` int(11) NOT NULL,
  `user_id` int(11) DEFAULT NULL,
  `score` decimal(5,2) DEFAULT NULL,
  `passed` tinyint(1) DEFAULT 0,
  `start_time` datetime DEFAULT NULL,
  `end_time` datetime DEFAULT NULL,
  `answers` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`answers`)),
  `created_at` timestamp NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `exam_schedules`
--

CREATE TABLE `exam_schedules` (
  `id` int(11) NOT NULL,
  `exam_date` date NOT NULL,
  `start_time` time DEFAULT '09:00:00',
  `end_time` time DEFAULT '17:00:00',
  `max_slots` int(11) DEFAULT 50,
  `available_slots` int(11) DEFAULT 50,
  `status` enum('active','inactive','full') DEFAULT 'active',
  `notes` text DEFAULT NULL,
  `created_by` int(11) DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `exam_schedules`
--

INSERT INTO `exam_schedules` (`id`, `exam_date`, `start_time`, `end_time`, `max_slots`, `available_slots`, `status`, `notes`, `created_by`, `created_at`, `updated_at`) VALUES
(1, '2025-09-24', '09:00:00', '17:00:00', 50, 50, 'active', 'Auto-generated exam date', NULL, '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(2, '2025-09-15', '09:00:00', '17:00:00', 50, 50, 'active', 'Auto-generated exam date', NULL, '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(3, '2025-09-25', '09:00:00', '17:00:00', 50, 50, 'active', 'Auto-generated exam date', NULL, '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(4, '2025-09-16', '09:00:00', '17:00:00', 50, 50, 'active', 'Auto-generated exam date', NULL, '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(5, '2025-09-26', '09:00:00', '17:00:00', 50, 50, 'active', 'Auto-generated exam date', NULL, '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(6, '2025-10-06', '09:00:00', '17:00:00', 50, 50, 'active', 'Auto-generated exam date', NULL, '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(7, '2025-09-17', '09:00:00', '17:00:00', 50, 50, 'active', 'Auto-generated exam date', NULL, '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(8, '2025-10-07', '09:00:00', '17:00:00', 50, 50, 'active', 'Auto-generated exam date', NULL, '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(9, '2025-09-18', '09:00:00', '17:00:00', 50, 50, 'active', 'Auto-generated exam date', NULL, '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(10, '2025-10-08', '09:00:00', '17:00:00', 50, 50, 'active', 'Auto-generated exam date', NULL, '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(11, '2025-09-19', '09:00:00', '17:00:00', 50, 50, 'active', 'Auto-generated exam date', NULL, '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(12, '2025-09-29', '09:00:00', '17:00:00', 50, 50, 'active', 'Auto-generated exam date', NULL, '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(13, '2025-10-09', '09:00:00', '17:00:00', 50, 50, 'active', 'Auto-generated exam date', NULL, '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(14, '2025-09-30', '09:00:00', '17:00:00', 50, 50, 'active', 'Auto-generated exam date', NULL, '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(15, '2025-10-10', '09:00:00', '17:00:00', 50, 50, 'active', 'Auto-generated exam date', NULL, '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(16, '2025-10-01', '09:00:00', '17:00:00', 50, 50, 'active', 'Auto-generated exam date', NULL, '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(17, '2025-09-22', '09:00:00', '17:00:00', 50, 50, 'active', 'Auto-generated exam date', NULL, '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(18, '2025-10-02', '09:00:00', '17:00:00', 50, 50, 'active', 'Auto-generated exam date', NULL, '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(32, '2025-09-23', '09:00:00', '17:00:00', 50, 50, 'active', 'Auto-generated exam date', NULL, '2025-09-16 04:11:27', '2025-09-16 04:11:27'),
(33, '2025-10-03', '09:00:00', '17:00:00', 50, 50, 'active', 'Auto-generated exam date', NULL, '2025-09-16 04:11:27', '2025-09-16 04:11:27'),
(34, '2025-10-13', '09:00:00', '17:00:00', 50, 50, 'active', 'Auto-generated exam date', NULL, '2025-09-16 04:11:27', '2025-09-16 04:11:27'),
(35, '2025-10-14', '09:00:00', '17:00:00', 50, 50, 'active', 'Auto-generated exam date', NULL, '2025-09-16 04:11:27', '2025-09-16 04:11:27'),
(36, '2025-10-15', '09:00:00', '17:00:00', 50, 50, 'active', 'Auto-generated exam date', NULL, '2025-09-16 04:11:27', '2025-09-16 04:11:27'),
(37, '2025-10-23', '09:00:00', '17:00:00', 50, 50, 'active', 'Auto-generated exam date', NULL, '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(38, '2025-10-24', '09:00:00', '17:00:00', 50, 50, 'active', 'Auto-generated exam date', NULL, '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(39, '2025-11-03', '09:00:00', '17:00:00', 50, 50, 'active', 'Auto-generated exam date', NULL, '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(40, '2025-11-04', '09:00:00', '17:00:00', 50, 50, 'active', 'Auto-generated exam date', NULL, '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(41, '2025-10-16', '09:00:00', '17:00:00', 50, 50, 'active', 'Auto-generated exam date', NULL, '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(42, '2025-11-05', '09:00:00', '17:00:00', 50, 50, 'active', 'Auto-generated exam date', NULL, '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(43, '2025-10-17', '09:00:00', '17:00:00', 50, 50, 'active', 'Auto-generated exam date', NULL, '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(44, '2025-10-27', '09:00:00', '17:00:00', 50, 50, 'active', 'Auto-generated exam date', NULL, '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(45, '2025-11-06', '09:00:00', '17:00:00', 50, 50, 'active', 'Auto-generated exam date', NULL, '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(46, '2025-10-28', '09:00:00', '17:00:00', 50, 50, 'active', 'Auto-generated exam date', NULL, '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(47, '2025-11-07', '09:00:00', '17:00:00', 50, 50, 'active', 'Auto-generated exam date', NULL, '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(48, '2025-10-29', '09:00:00', '17:00:00', 50, 50, 'active', 'Auto-generated exam date', NULL, '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(49, '2025-10-20', '09:00:00', '17:00:00', 50, 50, 'active', 'Auto-generated exam date', NULL, '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(50, '2025-10-30', '09:00:00', '17:00:00', 50, 50, 'active', 'Auto-generated exam date', NULL, '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(51, '2025-10-21', '09:00:00', '17:00:00', 50, 50, 'active', 'Auto-generated exam date', NULL, '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(52, '2025-10-31', '09:00:00', '17:00:00', 50, 50, 'active', 'Auto-generated exam date', NULL, '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(53, '2025-11-10', '09:00:00', '17:00:00', 50, 50, 'active', 'Auto-generated exam date', NULL, '2025-10-12 11:30:06', '2025-10-12 11:30:06');

-- --------------------------------------------------------

--
-- Table structure for table `exam_sessions`
--

CREATE TABLE `exam_sessions` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `package_id` int(11) NOT NULL,
  `scheduled_at` timestamp NULL DEFAULT NULL,
  `started_at` timestamp NULL DEFAULT NULL,
  `purchase_id` int(11) NOT NULL,
  `session_token` varchar(100) NOT NULL,
  `scheduled_date` datetime DEFAULT NULL,
  `start_time` timestamp NULL DEFAULT NULL,
  `end_time` timestamp NULL DEFAULT NULL,
  `duration_minutes` int(11) DEFAULT NULL,
  `questions_data` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`questions_data`)),
  `answers_data` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`answers_data`)),
  `current_question` int(11) DEFAULT 1,
  `score` decimal(5,2) DEFAULT NULL,
  `percentage` decimal(5,2) DEFAULT NULL,
  `passed` tinyint(1) DEFAULT 0,
  `time_spent` int(11) DEFAULT 0,
  `total_correct` int(11) DEFAULT 0,
  `total_incorrect` int(11) DEFAULT 0,
  `total_unanswered` int(11) DEFAULT 0,
  `result` enum('pass','fail','incomplete','in_progress') DEFAULT 'incomplete',
  `certificate_generated` tinyint(1) DEFAULT 0,
  `certificate_path` varchar(255) DEFAULT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `user_agent` text DEFAULT NULL,
  `browser_info` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`browser_info`)),
  `proctoring_data` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`proctoring_data`)),
  `flags` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`flags`)),
  `status` enum('scheduled','in_progress','completed','expired','cancelled') DEFAULT 'scheduled',
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `completed_at` timestamp NULL DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `exam_sessions`
--

INSERT INTO `exam_sessions` (`id`, `user_id`, `package_id`, `scheduled_at`, `started_at`, `purchase_id`, `session_token`, `scheduled_date`, `start_time`, `end_time`, `duration_minutes`, `questions_data`, `answers_data`, `current_question`, `score`, `percentage`, `passed`, `time_spent`, `total_correct`, `total_incorrect`, `total_unanswered`, `result`, `certificate_generated`, `certificate_path`, `ip_address`, `user_agent`, `browser_info`, `proctoring_data`, `flags`, `status`, `created_at`, `completed_at`) VALUES
(19, 52, 1, '2025-12-28 07:00:00', NULL, 31, 'EXAM_1766470607_7483', NULL, NULL, NULL, NULL, NULL, NULL, 1, NULL, NULL, 0, 0, 0, 0, 0, 'incomplete', 0, NULL, NULL, NULL, NULL, NULL, NULL, 'scheduled', '2025-12-23 06:16:47', NULL),
(20, 209, 1, '2026-01-22 13:00:00', NULL, 1025, 'EXAM_1768487245_2280', NULL, NULL, NULL, NULL, NULL, NULL, 1, NULL, NULL, 0, 0, 0, 0, 0, 'incomplete', 0, NULL, NULL, NULL, NULL, NULL, NULL, 'scheduled', '2026-01-15 14:27:25', NULL);

-- --------------------------------------------------------

--
-- Table structure for table `exam_time_slots`
--

CREATE TABLE `exam_time_slots` (
  `id` int(11) NOT NULL,
  `schedule_id` int(11) NOT NULL,
  `time_slot` time NOT NULL,
  `max_capacity` int(11) DEFAULT 10,
  `booked_count` int(11) DEFAULT 0,
  `status` enum('available','full','disabled') DEFAULT 'available',
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `exam_time_slots`
--

INSERT INTO `exam_time_slots` (`id`, `schedule_id`, `time_slot`, `max_capacity`, `booked_count`, `status`, `created_at`, `updated_at`) VALUES
(1, 1, '09:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(2, 2, '09:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(3, 3, '09:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(4, 4, '09:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(5, 5, '09:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(6, 6, '09:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(7, 7, '09:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(8, 8, '09:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(9, 9, '09:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(10, 10, '09:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(11, 11, '09:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(12, 12, '09:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(13, 13, '09:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(14, 14, '09:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(15, 15, '09:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(16, 16, '09:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(17, 17, '09:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(18, 18, '09:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(19, 1, '10:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(20, 2, '10:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(21, 3, '10:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(22, 4, '10:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(23, 5, '10:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(24, 6, '10:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(25, 7, '10:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(26, 8, '10:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(27, 9, '10:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(28, 10, '10:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(29, 11, '10:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(30, 12, '10:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(31, 13, '10:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(32, 14, '10:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(33, 15, '10:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(34, 16, '10:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(35, 17, '10:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(36, 18, '10:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(37, 1, '11:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(38, 2, '11:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(39, 3, '11:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(40, 4, '11:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(41, 5, '11:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(42, 6, '11:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(43, 7, '11:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(44, 8, '11:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(45, 9, '11:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(46, 10, '11:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(47, 11, '11:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(48, 12, '11:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(49, 13, '11:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(50, 14, '11:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(51, 15, '11:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(52, 16, '11:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(53, 17, '11:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(54, 18, '11:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(55, 1, '14:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(56, 2, '14:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(57, 3, '14:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(58, 4, '14:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(59, 5, '14:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(60, 6, '14:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(61, 7, '14:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(62, 8, '14:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(63, 9, '14:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(64, 10, '14:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(65, 11, '14:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(66, 12, '14:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(67, 13, '14:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(68, 14, '14:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(69, 15, '14:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(70, 16, '14:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(71, 17, '14:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(72, 18, '14:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(73, 1, '15:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(74, 2, '15:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(75, 3, '15:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(76, 4, '15:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(77, 5, '15:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(78, 6, '15:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(79, 7, '15:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(80, 8, '15:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(81, 9, '15:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(82, 10, '15:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(83, 11, '15:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(84, 12, '15:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(85, 13, '15:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(86, 14, '15:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(87, 15, '15:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(88, 16, '15:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(89, 17, '15:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(90, 18, '15:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(91, 1, '16:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(92, 2, '16:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(93, 3, '16:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(94, 4, '16:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(95, 5, '16:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(96, 6, '16:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(97, 7, '16:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(98, 8, '16:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(99, 9, '16:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(100, 10, '16:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(101, 11, '16:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(102, 12, '16:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(103, 13, '16:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(104, 14, '16:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(105, 15, '16:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(106, 16, '16:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(107, 17, '16:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(108, 18, '16:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(109, 1, '17:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(110, 2, '17:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(111, 3, '17:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(112, 4, '17:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(113, 5, '17:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(114, 6, '17:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(115, 7, '17:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(116, 8, '17:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(117, 9, '17:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(118, 10, '17:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(119, 11, '17:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(120, 12, '17:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(121, 13, '17:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(122, 14, '17:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(123, 15, '17:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(124, 16, '17:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(125, 17, '17:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(126, 18, '17:00:00', 10, 0, 'available', '2025-09-13 08:38:27', '2025-09-13 08:38:27'),
(128, 32, '09:00:00', 10, 0, 'available', '2025-09-16 04:11:27', '2025-09-16 04:11:27'),
(129, 33, '09:00:00', 10, 0, 'available', '2025-09-16 04:11:27', '2025-09-16 04:11:27'),
(130, 34, '09:00:00', 10, 0, 'available', '2025-09-16 04:11:27', '2025-09-16 04:11:27'),
(131, 35, '09:00:00', 10, 0, 'available', '2025-09-16 04:11:27', '2025-09-16 04:11:27'),
(132, 36, '09:00:00', 10, 0, 'available', '2025-09-16 04:11:27', '2025-09-16 04:11:27'),
(133, 32, '10:00:00', 10, 0, 'available', '2025-09-16 04:11:27', '2025-09-16 04:11:27'),
(134, 33, '10:00:00', 10, 0, 'available', '2025-09-16 04:11:27', '2025-09-16 04:11:27'),
(135, 34, '10:00:00', 10, 0, 'available', '2025-09-16 04:11:27', '2025-09-16 04:11:27'),
(136, 35, '10:00:00', 10, 0, 'available', '2025-09-16 04:11:27', '2025-09-16 04:11:27'),
(137, 36, '10:00:00', 10, 0, 'available', '2025-09-16 04:11:27', '2025-09-16 04:11:27'),
(138, 32, '11:00:00', 10, 0, 'available', '2025-09-16 04:11:27', '2025-09-16 04:11:27'),
(139, 33, '11:00:00', 10, 0, 'available', '2025-09-16 04:11:27', '2025-09-16 04:11:27'),
(140, 34, '11:00:00', 10, 0, 'available', '2025-09-16 04:11:27', '2025-09-16 04:11:27'),
(141, 35, '11:00:00', 10, 0, 'available', '2025-09-16 04:11:27', '2025-09-16 04:11:27'),
(142, 36, '11:00:00', 10, 0, 'available', '2025-09-16 04:11:27', '2025-09-16 04:11:27'),
(143, 32, '14:00:00', 10, 0, 'available', '2025-09-16 04:11:27', '2025-09-16 04:11:27'),
(144, 33, '14:00:00', 10, 0, 'available', '2025-09-16 04:11:27', '2025-09-16 04:11:27'),
(145, 34, '14:00:00', 10, 0, 'available', '2025-09-16 04:11:27', '2025-09-16 04:11:27'),
(146, 35, '14:00:00', 10, 0, 'available', '2025-09-16 04:11:27', '2025-09-16 04:11:27'),
(147, 36, '14:00:00', 10, 0, 'available', '2025-09-16 04:11:27', '2025-09-16 04:11:27'),
(148, 32, '15:00:00', 10, 0, 'available', '2025-09-16 04:11:27', '2025-09-16 04:11:27'),
(149, 33, '15:00:00', 10, 0, 'available', '2025-09-16 04:11:27', '2025-09-16 04:11:27'),
(150, 34, '15:00:00', 10, 0, 'available', '2025-09-16 04:11:27', '2025-09-16 04:11:27'),
(151, 35, '15:00:00', 10, 0, 'available', '2025-09-16 04:11:27', '2025-09-16 04:11:27'),
(152, 36, '15:00:00', 10, 0, 'available', '2025-09-16 04:11:27', '2025-09-16 04:11:27'),
(153, 32, '16:00:00', 10, 0, 'available', '2025-09-16 04:11:27', '2025-09-16 04:11:27'),
(154, 33, '16:00:00', 10, 0, 'available', '2025-09-16 04:11:27', '2025-09-16 04:11:27'),
(155, 34, '16:00:00', 10, 0, 'available', '2025-09-16 04:11:27', '2025-09-16 04:11:27'),
(156, 35, '16:00:00', 10, 0, 'available', '2025-09-16 04:11:27', '2025-09-16 04:11:27'),
(157, 36, '16:00:00', 10, 0, 'available', '2025-09-16 04:11:27', '2025-09-16 04:11:27'),
(158, 32, '17:00:00', 10, 0, 'available', '2025-09-16 04:11:27', '2025-09-16 04:11:27'),
(159, 33, '17:00:00', 10, 0, 'available', '2025-09-16 04:11:27', '2025-09-16 04:11:27'),
(160, 34, '17:00:00', 10, 0, 'available', '2025-09-16 04:11:27', '2025-09-16 04:11:27'),
(161, 35, '17:00:00', 10, 0, 'available', '2025-09-16 04:11:27', '2025-09-16 04:11:27'),
(162, 36, '17:00:00', 10, 0, 'available', '2025-09-16 04:11:27', '2025-09-16 04:11:27'),
(163, 37, '09:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(164, 38, '09:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(165, 39, '09:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(166, 40, '09:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(167, 41, '09:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(168, 42, '09:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(169, 43, '09:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(170, 44, '09:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(171, 45, '09:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(172, 46, '09:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(173, 47, '09:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(174, 48, '09:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(175, 49, '09:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(176, 50, '09:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(177, 51, '09:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(178, 52, '09:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(179, 53, '09:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(180, 37, '10:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(181, 38, '10:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(182, 39, '10:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(183, 40, '10:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(184, 41, '10:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(185, 42, '10:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(186, 43, '10:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(187, 44, '10:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(188, 45, '10:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(189, 46, '10:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(190, 47, '10:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(191, 48, '10:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(192, 49, '10:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(193, 50, '10:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(194, 51, '10:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(195, 52, '10:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(196, 53, '10:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(197, 37, '11:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(198, 38, '11:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(199, 39, '11:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(200, 40, '11:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(201, 41, '11:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(202, 42, '11:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(203, 43, '11:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(204, 44, '11:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(205, 45, '11:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(206, 46, '11:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(207, 47, '11:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(208, 48, '11:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(209, 49, '11:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(210, 50, '11:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(211, 51, '11:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(212, 52, '11:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(213, 53, '11:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(214, 37, '14:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(215, 38, '14:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(216, 39, '14:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(217, 40, '14:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(218, 41, '14:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(219, 42, '14:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(220, 43, '14:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(221, 44, '14:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(222, 45, '14:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(223, 46, '14:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(224, 47, '14:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(225, 48, '14:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(226, 49, '14:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(227, 50, '14:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(228, 51, '14:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(229, 52, '14:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(230, 53, '14:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(231, 37, '15:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(232, 38, '15:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(233, 39, '15:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(234, 40, '15:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(235, 41, '15:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(236, 42, '15:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(237, 43, '15:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(238, 44, '15:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(239, 45, '15:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(240, 46, '15:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(241, 47, '15:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(242, 48, '15:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(243, 49, '15:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(244, 50, '15:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(245, 51, '15:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(246, 52, '15:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(247, 53, '15:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(248, 37, '16:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(249, 38, '16:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(250, 39, '16:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(251, 40, '16:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(252, 41, '16:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(253, 42, '16:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(254, 43, '16:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(255, 44, '16:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(256, 45, '16:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(257, 46, '16:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(258, 47, '16:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(259, 48, '16:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(260, 49, '16:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(261, 50, '16:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(262, 51, '16:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(263, 52, '16:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(264, 53, '16:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(265, 37, '17:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(266, 38, '17:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(267, 39, '17:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(268, 40, '17:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(269, 41, '17:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(270, 42, '17:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(271, 43, '17:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(272, 44, '17:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(273, 45, '17:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(274, 46, '17:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(275, 47, '17:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(276, 48, '17:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(277, 49, '17:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(278, 50, '17:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(279, 51, '17:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(280, 52, '17:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06'),
(281, 53, '17:00:00', 10, 0, 'available', '2025-10-12 11:30:06', '2025-10-12 11:30:06');

-- --------------------------------------------------------

--
-- Table structure for table `file_access_nonces`
--

CREATE TABLE `file_access_nonces` (
  `id` int(11) NOT NULL,
  `nonce` varchar(64) NOT NULL,
  `user_id` int(11) NOT NULL,
  `file_id` int(11) NOT NULL,
  `folder_id` int(11) NOT NULL,
  `token_hash` varchar(128) NOT NULL,
  `expires_at` timestamp NOT NULL,
  `used` tinyint(1) DEFAULT 0,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `used_at` timestamp NULL DEFAULT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `user_agent_hash` varchar(64) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `file_access_tokens`
--

CREATE TABLE `file_access_tokens` (
  `id` int(11) NOT NULL,
  `token` varchar(64) NOT NULL,
  `file_id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `expires_at` datetime NOT NULL,
  `used` tinyint(1) DEFAULT 0,
  `created_at` timestamp NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `file_access_tokens`
--

INSERT INTO `file_access_tokens` (`id`, `token`, `file_id`, `user_id`, `expires_at`, `used`, `created_at`) VALUES
(1, '23fffe5463519d507d941be015106325', 85, 27, '2025-10-23 06:49:41', 0, '2025-10-23 06:44:41');

-- --------------------------------------------------------

--
-- Table structure for table `lms_access_logs`
--

CREATE TABLE `lms_access_logs` (
  `id` int(11) NOT NULL,
  `user_id` int(11) DEFAULT NULL,
  `folder_id` int(11) DEFAULT NULL,
  `file_id` int(11) DEFAULT NULL,
  `action` varchar(50) NOT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `user_agent` text DEFAULT NULL,
  `access_time` timestamp NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;

--
-- Dumping data for table `lms_access_logs`
--

INSERT INTO `lms_access_logs` (`id`, `user_id`, `folder_id`, `file_id`, `action`, `ip_address`, `user_agent`, `access_time`) VALUES
(7017, 27, 1, 146, 'preview_file', '2409:40d6:c:1a56:212d:f9f8:ba10:a649', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36', '2026-02-13 04:32:32'),
(7018, 27, 1, 146, 'preview_file', '2409:40d6:c:1a56:212d:f9f8:ba10:a649', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36', '2026-02-13 04:32:32'),
(7019, 27, 1, 146, 'preview_file', '2409:40d6:c:1a56:212d:f9f8:ba10:a649', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36', '2026-02-13 04:32:32'),
(7020, 27, 1, 146, 'preview_file', '157.49.158.157', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:147.0) Gecko/20100101 Firefox/147.0', '2026-02-14 16:03:20'),
(7021, 27, 1, 146, 'preview_file', '157.49.158.157', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:147.0) Gecko/20100101 Firefox/147.0', '2026-02-14 16:03:21'),
(7022, 27, 1, 146, 'preview_file', '157.49.158.157', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:147.0) Gecko/20100101 Firefox/147.0', '2026-02-14 16:03:31'),
(7023, 27, 1, 146, 'preview_file', '157.49.158.157', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:147.0) Gecko/20100101 Firefox/147.0', '2026-02-14 16:03:33'),
(7024, 129, 1, 146, 'preview_file', '106.192.80.170', 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Mobile Safari/537.36 OPR/95.0.0.0', '2026-02-27 14:56:46'),
(7025, 129, 1, 146, 'preview_file', '106.192.80.170', 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Mobile Safari/537.36 OPR/95.0.0.0', '2026-02-27 14:56:47'),
(7026, 129, 1, NULL, 'view', '106.192.80.170', 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Mobile Safari/537.36 OPR/95.0.0.0', '2026-02-27 14:56:50'),
(7027, 129, 1, 178, 'preview_file', '2401:4900:b7bc:da20:5c41:5f0c:5864:c444', 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Mobile Safari/537.36 OPR/95.0.0.0', '2026-02-27 14:57:43'),
(7028, 129, 1, 178, 'preview_file', '2401:4900:b7bc:da20:5c41:5f0c:5864:c444', 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Mobile Safari/537.36 OPR/95.0.0.0', '2026-02-27 14:57:46'),
(7029, 27, 1, 146, 'preview_file', '157.49.175.109', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36', '2026-02-27 16:16:16'),
(7030, 27, 1, 146, 'preview_file', '157.49.175.109', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36', '2026-02-27 16:16:18');

-- --------------------------------------------------------

--
-- Table structure for table `lms_download_tokens`
--

CREATE TABLE `lms_download_tokens` (
  `id` int(11) NOT NULL,
  `file_id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `token` varchar(64) NOT NULL,
  `expires_at` timestamp NOT NULL,
  `used` tinyint(1) NOT NULL DEFAULT 0,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;

-- --------------------------------------------------------

--
-- Table structure for table `lms_files`
--

CREATE TABLE `lms_files` (
  `id` int(11) NOT NULL,
  `folder_id` int(11) NOT NULL,
  `file_original_name` varchar(255) NOT NULL,
  `file_path` varchar(500) NOT NULL,
  `file_type` varchar(10) NOT NULL,
  `file_size` bigint(20) NOT NULL,
  `upload_date` timestamp NULL DEFAULT current_timestamp(),
  `uploaded_by` int(11) DEFAULT NULL,
  `is_streamed` tinyint(1) DEFAULT 0 COMMENT 'True for streamed video uploads',
  `upload_method` enum('direct','chunked','streaming') DEFAULT 'direct' COMMENT 'Upload method used',
  `chunk_count` int(11) DEFAULT NULL COMMENT 'Number of chunks for chunked uploads',
  `streaming_session_key` varchar(255) DEFAULT NULL COMMENT 'Reference to streaming session',
  `processing_status` enum('pending','processing','completed','failed') DEFAULT 'pending' COMMENT 'Video processing status',
  `thumbnail_path` varchar(500) DEFAULT NULL COMMENT 'Path to generated thumbnail',
  `duration_seconds` int(11) DEFAULT NULL COMMENT 'Video duration in seconds',
  `resolution` varchar(20) DEFAULT NULL COMMENT 'Video resolution (e.g., 1920x1080)',
  `bitrate` int(11) DEFAULT NULL COMMENT 'Video bitrate in kbps',
  `codec` varchar(50) DEFAULT NULL COMMENT 'Video codec information',
  `security_level` enum('standard','confidential','secret','top_secret') DEFAULT 'standard',
  `access_count` int(11) DEFAULT 0,
  `last_accessed` timestamp NULL DEFAULT NULL,
  `security_flags` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`security_flags`))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;

--
-- Dumping data for table `lms_files`
--

INSERT INTO `lms_files` (`id`, `folder_id`, `file_original_name`, `file_path`, `file_type`, `file_size`, `upload_date`, `uploaded_by`, `is_streamed`, `upload_method`, `chunk_count`, `streaming_session_key`, `processing_status`, `thumbnail_path`, `duration_seconds`, `resolution`, `bitrate`, `codec`, `security_level`, `access_count`, `last_accessed`, `security_flags`) VALUES
(146, 1, 'intro to course.mp4', 'uploads/lms/1/1764603007_692db47f0701f.mp4', 'mp4', 11196064, '2025-12-01 15:30:07', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(147, 1, 'Cia traids.mp4', 'uploads/lms/1/1764603054_692db4ae150e5.mp4', 'mp4', 37945510, '2025-12-01 15:30:54', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(148, 1, 'scope and purpose.mp4', 'uploads/lms/1/1764603092_692db4d4dec11.mp4', 'mp4', 43151040, '2025-12-01 15:31:32', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(149, 1, 'types of testers.mp4', 'uploads/lms/1/1764603147_692db50b11434.mp4', 'mp4', 19687892, '2025-12-01 15:32:27', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(150, 1, 'nist.mp4', 'uploads/lms/1/1764603199_692db53f503fa.mp4', 'mp4', 11689513, '2025-12-01 15:33:19', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(151, 1, 'owasp .mp4', 'uploads/lms/1/1764603203_692db543cf6a8.mp4', 'mp4', 42713361, '2025-12-01 15:33:23', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(152, 1, 'Pt methodology.mp4', 'uploads/lms/1/1764603206_692db54661807.mp4', 'mp4', 17273108, '2025-12-01 15:33:26', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(153, 1, 'automated testing.mp4', 'uploads/lms/1/1764603368_692db5e845a56.mp4', 'mp4', 10620150, '2025-12-01 15:36:08', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(154, 1, 'nikto.mp4', 'uploads/lms/1/1764603371_692db5eb9bf1c.mp4', 'mp4', 10278395, '2025-12-01 15:36:11', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(155, 1, 'openvas.mp4', 'uploads/lms/1/1764603374_692db5ee4aa77.mp4', 'mp4', 10241392, '2025-12-01 15:36:14', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(156, 1, 'web scan.mp4', 'uploads/lms/1/1764603378_692db5f205ccf.mp4', 'mp4', 16072271, '2025-12-01 15:36:18', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(157, 1, 'zap.mp4', 'uploads/lms/1/1764603380_692db5f4b06cb.mp4', 'mp4', 13682890, '2025-12-01 15:36:20', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(164, 1, 'information gathering.mp4', 'uploads/lms/1/1764603451_692db63ba205b.mp4', 'mp4', 22030644, '2025-12-01 15:37:31', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(167, 1, 'subdomain.mp4', 'uploads/lms/1/1764603603_692db6d309f58.mp4', 'mp4', 27496294, '2025-12-01 15:40:03', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(168, 1, 'directories.mp4', 'uploads/lms/1/1764603638_692db6f60208e.mp4', 'mp4', 6057519, '2025-12-01 15:40:38', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(169, 1, 'burp.mp4', 'uploads/lms/1/1764603668_692db714eef2e.mp4', 'mp4', 13367670, '2025-12-01 15:41:08', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(170, 1, 'burp suite 1.mp4', 'uploads/lms/1/1764603811_692db7a3db262.mp4', 'mp4', 14485524, '2025-12-01 15:43:31', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(171, 1, 'burp suite 2.mp4', 'uploads/lms/1/1764603813_692db7a5c1c2b.mp4', 'mp4', 7632252, '2025-12-01 15:43:33', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(172, 1, 'ssl.mp4', 'uploads/lms/1/1764603840_692db7c014b4e.mp4', 'mp4', 27233518, '2025-12-01 15:44:00', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(173, 1, 'fofa.mp4', 'uploads/lms/1/1764603867_692db7db654d7.mp4', 'mp4', 7573227, '2025-12-01 15:44:27', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(174, 1, 'hunter.mp4', 'uploads/lms/1/1764603892_692db7f4bf684.mp4', 'mp4', 10856071, '2025-12-01 15:44:52', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(175, 1, 'authentication.mp4', 'uploads/lms/1/1764603972_692db8443b1fb.mp4', 'mp4', 32972058, '2025-12-01 15:46:12', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(176, 1, 'command injection(1).mp4', 'uploads/lms/1/1764603976_692db848275c2.mp4', 'mp4', 13812188, '2025-12-01 15:46:16', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(177, 1, 'dos.mp4', 'uploads/lms/1/1764603979_692db84ba12cc.mp4', 'mp4', 20486442, '2025-12-01 15:46:19', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(178, 1, 'file upload.mp4', 'uploads/lms/1/1764603982_692db84e98e3e.mp4', 'mp4', 12633406, '2025-12-01 15:46:22', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(179, 1, 'idor.mp4', 'uploads/lms/1/1764603986_692db8520a94b.mp4', 'mp4', 15806135, '2025-12-01 15:46:26', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(180, 1, 'phishing(1).mp4', 'uploads/lms/1/1764603989_692db8550ad3a.mp4', 'mp4', 12198144, '2025-12-01 15:46:29', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(181, 1, 'sql attack.mp4', 'uploads/lms/1/1764603992_692db858d7871.mp4', 'mp4', 18963977, '2025-12-01 15:46:32', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(182, 1, 'xss.mp4', 'uploads/lms/1/1764603996_692db85c28203.mp4', 'mp4', 16432994, '2025-12-01 15:46:36', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(183, 1, 'ipvoid.mp4', 'uploads/lms/1/1764604028_692db87c155a9.mp4', 'mp4', 21389140, '2025-12-01 15:47:08', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(184, 1, 'p0f(1).mp4', 'uploads/lms/1/1764604030_692db87e95ad8.mp4', 'mp4', 11550418, '2025-12-01 15:47:10', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(185, 1, 'shodan.io.mp4', 'uploads/lms/1/1764604034_692db882a8fe8.mp4', 'mp4', 24299133, '2025-12-01 15:47:14', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(186, 1, 'tcpdump.mp4', 'uploads/lms/1/1764604040_692db88815821.mp4', 'mp4', 33722210, '2025-12-01 15:47:20', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(187, 1, 'wireshark.mp4', 'uploads/lms/1/1764604044_692db88c3eb36.mp4', 'mp4', 27416176, '2025-12-01 15:47:24', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(188, 1, 'yougetsignal.mp4', 'uploads/lms/1/1764604112_692db8d0b97b2.mp4', 'mp4', 7380715, '2025-12-01 15:48:32', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(189, 1, 'angryip.mp4', 'uploads/lms/1/1764604182_692db9165a84a.mp4', 'mp4', 11552764, '2025-12-01 15:49:42', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(190, 1, 'net discover.mp4', 'uploads/lms/1/1764604185_692db9198782c.mp4', 'mp4', 12346944, '2025-12-01 15:49:45', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(191, 1, 'nmap 1.mp4', 'uploads/lms/1/1764604188_692db91c68571.mp4', 'mp4', 12286227, '2025-12-01 15:49:48', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(192, 1, 'nmap 2.mp4', 'uploads/lms/1/1764604191_692db91fccd8f.mp4', 'mp4', 19493120, '2025-12-01 15:49:51', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(193, 1, 'uniscan.mp4', 'uploads/lms/1/1764604194_692db92223121.mp4', 'mp4', 6864318, '2025-12-01 15:49:54', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(194, 1, 'zenmap.mp4', 'uploads/lms/1/1764604198_692db92635e23.mp4', 'mp4', 16506691, '2025-12-01 15:49:58', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(195, 1, 'anonymous.mp4', 'uploads/lms/1/1764604244_692db9548696d.mp4', 'mp4', 16925188, '2025-12-01 15:50:44', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(197, 1, 'anonymous.mp4', 'uploads/lms/1/1766152179_694557f3e2f98.mp4', 'mp4', 16925188, '2025-12-19 13:49:39', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(198, 1, 'dark web python.mp4', 'uploads/lms/1/1766152181_694557f5e40f3.mp4', 'mp4', 19364291, '2025-12-19 13:49:41', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(199, 1, 'dehashed.mp4', 'uploads/lms/1/1766152183_694557f7b95ef.mp4', 'mp4', 14128735, '2025-12-19 13:49:43', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(200, 1, 'haveibeenpawned.mp4', 'uploads/lms/1/1766152185_694557f972f3a.mp4', 'mp4', 13473921, '2025-12-19 13:49:45', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(201, 1, 'macchanger.mp4', 'uploads/lms/1/1766152187_694557fb190bf.mp4', 'mp4', 12589984, '2025-12-19 13:49:47', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(202, 1, 'open stego.mp4', 'uploads/lms/1/1766152188_694557fcc7214.mp4', 'mp4', 13115675, '2025-12-19 13:49:48', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(203, 1, 'steghide.mp4', 'uploads/lms/1/1766152190_694557fe856d7.mp4', 'mp4', 12996370, '2025-12-19 13:49:50', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(204, 1, 'stegnigraphy.mp4', 'uploads/lms/1/1766152191_694557ffe5e43.mp4', 'mp4', 7264093, '2025-12-19 13:49:51', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(205, 1, 'CIA.html', 'uploads/lms/1/1766158153_69456f49512fd.html', 'html', 18077, '2025-12-19 15:29:13', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(206, 1, 'MANUAL.html', 'uploads/lms/1/1766158189_69456f6dabfb4.html', 'html', 19880, '2025-12-19 15:29:49', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(207, 1, 'METHOD.html', 'uploads/lms/1/1766158190_69456f6ee5bc3.html', 'html', 19803, '2025-12-19 15:29:50', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(208, 1, 'AUTO.html', 'uploads/lms/1/1766158263_69456fb71d79a.html', 'html', 19821, '2025-12-19 15:31:03', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(209, 1, 'SCOPE.html', 'uploads/lms/1/1766158294_69456fd6e658f.html', 'html', 20174, '2025-12-19 15:31:34', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(210, 1, 'dorking.mp4', 'uploads/lms/1/1769173876_69737374646be.mp4', 'mp4', 11989670, '2026-01-23 13:11:16', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(211, 1, 'information gathering.mp4', 'uploads/lms/1/1769173878_697373766a612.mp4', 'mp4', 7530265, '2026-01-23 13:11:18', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(212, 1, 'maxphish.mp4', 'uploads/lms/1/1769173881_6973737954e46.mp4', 'mp4', 15026674, '2026-01-23 13:11:21', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(213, 1, 'camphish.mp4', 'uploads/lms/1/1769176060_69737bfc647b1.mp4', 'mp4', 13489323, '2026-01-23 13:47:40', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(214, 1, 'camphish.mp4', 'uploads/lms/1/1769874372_697e23c4d78d2.mp4', 'mp4', 13489323, '2026-01-31 15:46:12', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(215, 1, 'dorking.mp4', 'uploads/lms/1/1769874374_697e23c657885.mp4', 'mp4', 11989670, '2026-01-31 15:46:14', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(216, 1, 'information gathering.mp4', 'uploads/lms/1/1769874376_697e23c86b300.mp4', 'mp4', 7530265, '2026-01-31 15:46:16', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(217, 1, 'lfi.mp4', 'uploads/lms/1/1769874378_697e23ca5c32d.mp4', 'mp4', 6360456, '2026-01-31 15:46:18', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(218, 1, 'maxphish.mp4', 'uploads/lms/1/1769874380_697e23cce5c25.mp4', 'mp4', 15026674, '2026-01-31 15:46:20', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(219, 1, 'setoolkit.mp4', 'uploads/lms/1/1769874383_697e23cfbfaed.mp4', 'mp4', 12706057, '2026-01-31 15:46:23', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(220, 1, 'the harvester.mp4', 'uploads/lms/1/1769874386_697e23d20a59f.mp4', 'mp4', 16501412, '2026-01-31 15:46:26', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(221, 1, 'WHO IS.mp4', 'uploads/lms/1/1769874388_697e23d47e82e.mp4', 'mp4', 9631072, '2026-01-31 15:46:28', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL),
(222, 1, 'wayback.mp4', 'uploads/lms/1/1769874899_697e25d3412cc.mp4', 'mp4', 6576882, '2026-01-31 15:54:59', 1, 0, 'direct', NULL, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, 'standard', 0, NULL, NULL);

-- --------------------------------------------------------

--
-- Table structure for table `lms_file_tags`
--

CREATE TABLE `lms_file_tags` (
  `id` int(11) NOT NULL,
  `file_id` int(11) NOT NULL,
  `tag_name` varchar(100) NOT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `lms_folders`
--

CREATE TABLE `lms_folders` (
  `id` int(11) NOT NULL,
  `folder_name` varchar(255) NOT NULL,
  `folder_slug` varchar(255) DEFAULT NULL,
  `description` text DEFAULT NULL,
  `parent_id` int(11) DEFAULT NULL,
  `download_allowed` tinyint(1) DEFAULT 1,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `security_level` enum('standard','confidential','secret','top_secret') DEFAULT 'standard',
  `access_count` int(11) DEFAULT 0,
  `last_accessed` timestamp NULL DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;

--
-- Dumping data for table `lms_folders`
--

INSERT INTO `lms_folders` (`id`, `folder_name`, `folder_slug`, `description`, `parent_id`, `download_allowed`, `created_at`, `updated_at`, `security_level`, `access_count`, `last_accessed`) VALUES
(1, 'CEHA', 'ceha', 'Root folder for LMS system', NULL, 0, '2025-11-07 10:12:35', '2025-11-21 05:28:50', 'standard', 0, NULL),
(53, 'Labs', 'labs', 'asdfasfd', NULL, 0, '2026-01-16 05:36:47', '2026-01-16 05:36:47', 'standard', 0, NULL);

-- --------------------------------------------------------

--
-- Table structure for table `lms_folder_permissions`
--

CREATE TABLE `lms_folder_permissions` (
  `id` int(11) NOT NULL,
  `folder_id` int(11) NOT NULL,
  `access_type` varchar(20) NOT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;

--
-- Dumping data for table `lms_folder_permissions`
--

INSERT INTO `lms_folder_permissions` (`id`, `folder_id`, `access_type`, `created_at`) VALUES
(174, 1, 'public', '2025-11-21 05:28:50'),
(175, 1, 'CEHA', '2025-11-21 05:28:50'),
(176, 1, 'CEHS', '2025-11-21 05:28:50'),
(178, 53, 'CEHA', '2026-01-16 05:36:47');

-- --------------------------------------------------------

--
-- Table structure for table `lms_security_events`
--

CREATE TABLE `lms_security_events` (
  `id` int(11) NOT NULL,
  `user_id` int(11) DEFAULT NULL,
  `file_id` int(11) DEFAULT NULL,
  `event_type` varchar(100) NOT NULL,
  `token` varchar(255) DEFAULT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `user_agent` text DEFAULT NULL,
  `event_time` timestamp NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `lms_security_events`
--

INSERT INTO `lms_security_events` (`id`, `user_id`, `file_id`, `event_type`, `token`, `ip_address`, `user_agent`, `event_time`) VALUES
(7, 27, 68, 'direct_url_blocked', NULL, '152.59.90.166', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', '2025-10-23 04:50:23'),
(8, 27, 68, 'direct_url_blocked', NULL, '152.59.90.166', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:144.0) Gecko/20100101 Firefox/144.0', '2025-10-23 05:51:17');

-- --------------------------------------------------------

--
-- Table structure for table `lms_settings`
--

CREATE TABLE `lms_settings` (
  `id` int(11) NOT NULL,
  `setting_key` varchar(100) NOT NULL,
  `setting_value` text DEFAULT NULL,
  `setting_type` enum('string','number','boolean','json') DEFAULT 'string',
  `description` text DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `lms_settings`
--

INSERT INTO `lms_settings` (`id`, `setting_key`, `setting_value`, `setting_type`, `description`, `created_at`, `updated_at`) VALUES
(1, 'max_file_size', '1073741824', 'number', 'Max file size', '2025-11-04 12:11:44', '2025-11-04 12:11:44'),
(2, 'allowed_extensions', 'mp4,avi,mkv,mov,wmv,flv,webm,jpg,jpeg,png,gif,bmp,svg,webp,pdf,doc,docx,txt,rtf,odt,xls,xlsx,ppt,pptx,odp,zip,rar,7z,tar,gz,bz2,php,js,html,htm,css,py,java,cpp,c,cs,rb,go,rs,swift,kt,sql,xml,json,yaml,yml', 'string', 'Allowed extensions', '2025-11-04 12:11:44', '2025-11-04 12:11:44'),
(3, 'enable_preview', '1', 'number', 'Enable preview', '2025-11-04 12:11:44', '2025-11-04 12:11:44'),
(4, 'enable_download', '1', 'number', 'Enable download', '2025-11-04 12:11:44', '2025-11-04 12:11:44'),
(5, 'enable_logging', '1', 'number', 'Enable logging', '2025-11-04 12:11:44', '2025-11-04 12:11:44'),
(6, 'max_upload_speed', '0', 'number', 'Max upload speed', '2025-11-04 12:11:44', '2025-11-04 12:11:44'),
(7, 'concurrent_uploads', '5', 'number', 'Concurrent uploads', '2025-11-04 12:11:44', '2025-11-04 12:11:44');

-- --------------------------------------------------------

--
-- Table structure for table `lms_upload_sessions`
--

CREATE TABLE `lms_upload_sessions` (
  `id` int(11) NOT NULL,
  `upload_id` varchar(100) NOT NULL,
  `folder_id` int(11) NOT NULL DEFAULT 1,
  `user_id` int(11) NOT NULL DEFAULT 1,
  `file_name` varchar(255) DEFAULT NULL,
  `file_size` bigint(20) DEFAULT 0,
  `file_type` varchar(100) DEFAULT NULL,
  `method` varchar(50) DEFAULT 'auto',
  `status` enum('initializing','active','paused','completed','failed','cancelled','streaming') DEFAULT 'initializing',
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `ip_address` varchar(45) DEFAULT NULL,
  `user_agent` text DEFAULT NULL,
  `upload_speed` decimal(10,2) DEFAULT 0.00,
  `total_time` decimal(10,2) DEFAULT 0.00,
  `bytes_uploaded` bigint(20) DEFAULT 0,
  `progress_percent` decimal(5,2) DEFAULT 0.00,
  `file_id` int(11) DEFAULT NULL,
  `error_message` text DEFAULT NULL,
  `file_hash` varchar(64) DEFAULT NULL,
  `retry_count` int(11) DEFAULT 0,
  `completed_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `total_files` int(11) DEFAULT 0,
  `total_size` bigint(20) DEFAULT 0,
  `uploaded_files` int(11) DEFAULT 0,
  `uploaded_size` bigint(20) DEFAULT 0,
  `upload_method` enum('chunk','stream','parallel_chunk','resumable','direct','auto') DEFAULT 'auto',
  `started_at` timestamp NULL DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `login_attempts`
--

CREATE TABLE `login_attempts` (
  `id` int(11) NOT NULL,
  `email` varchar(100) DEFAULT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `success` tinyint(1) DEFAULT 0,
  `attempt_time` timestamp NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `password_resets`
--

CREATE TABLE `password_resets` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `email` varchar(255) NOT NULL,
  `token` varchar(255) NOT NULL,
  `expires_at` datetime NOT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `password_resets`
--

INSERT INTO `password_resets` (`id`, `user_id`, `email`, `token`, `expires_at`, `created_at`) VALUES
(3, 13, 'amitkumarnalwa9@gmail.com', '87fb15584d32ef9c73d408fed09f7755be40a7883df569d9a88807d3238391af', '2025-11-11 10:34:25', '2025-11-11 04:54:25'),
(19, 177, 'millerjk24@gmail.com', '3b78a295c755ba6b95532bd64189834901d5377ce432ddaa203cd1f6533fd38a', '2025-12-31 03:24:40', '2025-12-30 21:44:40'),
(26, 29, 'vamsilakshmisatyakoppineedi@gmail.com', '08383d59ba2a0ae9920973f5ba30a6f4c8f78e9eb5e0739f9d31f42893ab5ac9', '2026-01-23 15:10:57', '2026-01-23 09:30:57');

-- --------------------------------------------------------

--
-- Table structure for table `payment_logs`
--

CREATE TABLE `payment_logs` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `action` varchar(100) NOT NULL,
  `razorpay_order_id` varchar(100) DEFAULT NULL,
  `razorpay_payment_id` varchar(100) DEFAULT NULL,
  `amount` decimal(10,2) DEFAULT NULL,
  `currency` varchar(10) DEFAULT 'INR',
  `status` varchar(50) DEFAULT NULL,
  `details` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`details`)),
  `created_at` timestamp NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `purchased_courses`
--

CREATE TABLE `purchased_courses` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `course_id` int(11) DEFAULT NULL,
  `exam_package_id` int(11) DEFAULT NULL,
  `source` enum('academy','exam_package','migration') DEFAULT 'academy',
  `purchase_date` timestamp NOT NULL DEFAULT current_timestamp(),
  `amount` decimal(10,2) DEFAULT 0.00,
  `currency` varchar(3) DEFAULT 'INR',
  `payment_method` varchar(50) DEFAULT NULL,
  `transaction_id` varchar(100) DEFAULT NULL,
  `status` enum('active','expired','refunded','pending') DEFAULT 'active',
  `progress` int(11) DEFAULT 0,
  `completed_lessons` int(11) DEFAULT 0,
  `total_lessons` int(11) DEFAULT 0,
  `time_spent` int(11) DEFAULT 0,
  `last_accessed` timestamp NULL DEFAULT NULL,
  `certificate_issued` tinyint(1) DEFAULT 0,
  `certificate_number` varchar(100) DEFAULT NULL,
  `certificate_url` varchar(500) DEFAULT NULL,
  `issued_at` timestamp NULL DEFAULT NULL,
  `expires_at` timestamp NULL DEFAULT NULL,
  `completion_date` timestamp NULL DEFAULT NULL,
  `access_granted_ip` varchar(45) DEFAULT NULL,
  `notes` text DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Triggers `purchased_courses`
--
DELIMITER $$
CREATE TRIGGER `update_course_enrollment` AFTER INSERT ON `purchased_courses` FOR EACH ROW BEGIN
  IF NEW.course_id IS NOT NULL THEN
    UPDATE `courses` SET
      enrollments = enrollments + 1
    WHERE id = NEW.course_id;
  END IF;
END
$$
DELIMITER ;

-- --------------------------------------------------------

--
-- Table structure for table `questions`
--

CREATE TABLE `questions` (
  `id` int(11) NOT NULL,
  `category_id` int(11) DEFAULT NULL,
  `package_id` int(11) DEFAULT NULL,
  `question_text` text NOT NULL,
  `question_type` enum('multiple_choice','true_false','fill_blank','scenario') DEFAULT 'multiple_choice',
  `option_a` varchar(500) DEFAULT NULL,
  `option_b` varchar(500) DEFAULT NULL,
  `option_c` varchar(500) DEFAULT NULL,
  `option_d` varchar(500) DEFAULT NULL,
  `correct_answer` varchar(10) NOT NULL,
  `explanation` text DEFAULT NULL,
  `difficulty` enum('easy','medium','hard') DEFAULT 'medium',
  `points` int(11) DEFAULT 1,
  `image_url` varchar(255) DEFAULT NULL,
  `code_snippet` text DEFAULT NULL,
  `time_limit` int(11) DEFAULT 60,
  `status` enum('active','inactive','review') DEFAULT 'active',
  `created_by` int(11) DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `questions`
--

INSERT INTO `questions` (`id`, `category_id`, `package_id`, `question_text`, `question_type`, `option_a`, `option_b`, `option_c`, `option_d`, `correct_answer`, `explanation`, `difficulty`, `points`, `image_url`, `code_snippet`, `time_limit`, `status`, `created_by`, `created_at`, `updated_at`) VALUES
(1, 1, 1, 'Which of the following is the first phase of ethical hacking?', 'multiple_choice', 'Reconnaissance', 'Scanning', 'Enumeration', 'Vulnerability Assessment', 'A', 'Reconnaissance is the first phase where information gathering about the target is performed without directly interacting with the target systems.', 'easy', 1, NULL, NULL, 60, 'active', NULL, '2025-07-18 02:05:05', '2025-07-18 02:05:05'),
(2, 1, 1, 'What port does SSH typically use?', 'multiple_choice', '21', '22', '23', '25', 'B', 'SSH (Secure Shell) typically uses port 22 for encrypted remote access communications.', 'easy', 1, NULL, NULL, 60, 'active', NULL, '2025-07-18 02:05:05', '2025-07-18 02:05:05'),
(3, 1, 1, 'Which Nmap scan type is considered stealthy and doesn\'t complete the TCP three-way handshake?', 'multiple_choice', 'TCP Connect Scan (-sT)', 'SYN Scan (-sS)', 'UDP Scan (-sU)', 'FIN Scan (-sF)', 'B', 'SYN scan (-sS) is stealthy because it sends SYN packets but doesn\'t complete the three-way handshake, making it harder to detect.', 'medium', 2, NULL, NULL, 60, 'active', NULL, '2025-07-18 02:05:05', '2025-07-18 02:05:05');

-- --------------------------------------------------------

--
-- Table structure for table `rate_limits`
--

CREATE TABLE `rate_limits` (
  `id` int(11) NOT NULL,
  `ip_address` varchar(45) NOT NULL,
  `action_type` varchar(50) NOT NULL,
  `attempt_count` int(11) DEFAULT 1,
  `window_start` timestamp NULL DEFAULT current_timestamp(),
  `blocked_until` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `remember_tokens`
--

CREATE TABLE `remember_tokens` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `token` varchar(255) NOT NULL,
  `expires_at` timestamp NOT NULL,
  `used_at` timestamp NULL DEFAULT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `user_agent` text DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `remember_tokens`
--

INSERT INTO `remember_tokens` (`id`, `user_id`, `token`, `expires_at`, `used_at`, `ip_address`, `user_agent`, `created_at`) VALUES
(1, 26, '271c7128dbb74b6dc6b09475e4e87aa9d8cfff427b9eb8df3aa528aaa44d86be', '2025-09-30 15:57:29', NULL, NULL, NULL, '2025-08-31 10:27:29'),
(2, 13, '58805b2f51a84d00c55ccb0d5190145a5de2111be85a272e2cf069a04795a653', '2025-10-10 14:03:14', NULL, NULL, NULL, '2025-09-10 08:33:14'),
(3, 27, '365c0124341d85177a6d0f0143d966d24b3dd3c2354a87f9e7311845da0690eb', '2025-10-13 13:26:48', NULL, NULL, NULL, '2025-09-13 07:56:48'),
(4, 27, '1fd7e0006325dd820e40181eaa3e859d2851c522f05968b83f5d8f9dad81cb70', '2025-10-13 13:46:37', NULL, NULL, NULL, '2025-09-13 08:16:37'),
(5, 13, 'ff0a62fa9f1bbe66d3f8fb13b4f6017f43e429959583312072456798501be4ff', '2025-10-18 10:47:26', NULL, NULL, NULL, '2025-09-18 05:17:26'),
(6, 13, 'ad135f3987ab884fb88ab24e0a997df22aa2a4c51e43a6111d624711d02e3680', '2025-10-18 11:03:06', NULL, NULL, NULL, '2025-09-18 05:33:06'),
(7, 27, '1e4f609ba43104f3e4f2987549e4287145623c2a919160546ce8d42eb7f07e5e', '2025-10-18 12:57:38', NULL, NULL, NULL, '2025-09-18 07:27:38'),
(8, 28, '48186d4cf091d80abb5e961cdf953fd3bd96a0eb43d277ea1451c5b4da37b138', '2025-10-19 09:35:47', NULL, NULL, NULL, '2025-09-19 04:05:47'),
(9, 13, '902c6a6db6f2a159b85803535e6f97b5a91515e196e150cf61ebede9e2b87408', '2025-10-19 10:11:53', NULL, NULL, NULL, '2025-09-19 04:41:53'),
(10, 27, 'c19db01e53bfecd4ad0fcab367ac3e10dbf92bb234bf6c933f0e9e2cc5c7880a', '2025-10-21 17:48:04', NULL, NULL, NULL, '2025-09-21 12:18:04'),
(11, 13, 'd92f739cabf2fe8ca7ac340aaa27cbb6d4eb1a968d4e86aed41481f81770e105', '2025-10-22 09:30:57', NULL, NULL, NULL, '2025-09-22 04:00:57'),
(12, 30, 'd1f4de59672c696fc2351b126a3bade23348abe815857d1e9775612d0d0898b4', '2025-10-31 13:03:55', NULL, NULL, NULL, '2025-10-01 07:33:55'),
(13, 27, 'c1c813842858afcf972c143a204ff15be26e52d5141b5ad357dc1e9df1801854', '2025-11-04 19:56:45', NULL, NULL, NULL, '2025-10-05 14:26:45'),
(14, 34, '151392e11d4500fd7ea2ccb1871e5db8e0365549dda4e17291853c9f627589e0', '2025-11-04 20:04:40', NULL, NULL, NULL, '2025-10-05 14:34:40'),
(15, 27, '8583ce882b3194a8d14c12d23a3276f209c4107c17eb2b39049fde5b4a88f643', '2025-11-17 11:51:47', NULL, NULL, NULL, '2025-10-18 06:21:47'),
(16, 38, '3dc1a3383c26c085a142adf767b03ed96035b8b27bb329af6d48103e6e05fd3c', '2025-12-02 17:45:39', NULL, NULL, NULL, '2025-11-02 12:15:39'),
(17, 27, 'ec4868b2f658c24710876e9e3bbd0dcd59fd9e2b92307543667f27c44f25ea3a', '2025-12-03 13:18:14', NULL, NULL, NULL, '2025-11-03 07:48:14'),
(18, 27, '96fce8aecc90bec815a5db2289389317930a929edc85deec371c1ecc3a66370e', '2025-12-06 11:41:31', NULL, NULL, NULL, '2025-11-06 06:11:31'),
(19, 27, '8329b1e3e443f260b70fb062c4066284727921622c7ff42a25be403cb465ddfb', '2025-12-06 12:15:24', NULL, NULL, NULL, '2025-11-06 06:45:24'),
(20, 27, '5bd81d9e0e6a3c6f55f98aa78d33e907eb44a729b8551e4032cc99b4ccfb472a', '2025-12-06 12:34:47', NULL, NULL, NULL, '2025-11-06 07:04:47'),
(21, 27, '559783b48d37550f4ba6038f167204de1df1ef6c0559af82e362731ec7677e5b', '2025-12-12 11:15:19', NULL, NULL, NULL, '2025-11-12 05:45:19'),
(22, 27, 'b210f7f5b1f385d95ba667d37a43da1fea055121b872e00bc71b370194809987', '2025-12-12 19:12:52', NULL, NULL, NULL, '2025-11-12 13:42:52'),
(23, 27, '84a5b0b65855844ac4e6e9f7a39f5ed9b33ff6166864ea68f48d5a2e1fed879a', '2025-12-14 09:53:17', NULL, NULL, NULL, '2025-11-14 04:23:17'),
(24, 43, '88f860846f20a844a630055e41a2124490fa7aca19d188eeb4ab839ff08e6529', '2025-12-14 13:32:30', NULL, NULL, NULL, '2025-11-14 08:02:30'),
(25, 47, 'aef79e94b4f283f7ede4f38f6dcef1e811126b42dbd1e08024b3ea317156e663', '2025-12-20 03:14:18', NULL, NULL, NULL, '2025-11-19 21:44:18'),
(26, 48, '421728c63bec17e5c25208443a988c0bb22ebbd5740a670820fb5cb9ac480ee1', '2025-12-20 22:56:44', NULL, NULL, NULL, '2025-11-20 17:26:44'),
(27, 21, 'f650c175f96689afe3018656ad29f15a4fa6c9a6ca82a1f5403a4614a1e37213', '2025-12-21 17:41:28', NULL, NULL, NULL, '2025-11-21 12:11:28'),
(28, 50, 'cce81d4a43a1b18308ac825efc4d4c75c9badfe6ee9b88f3cf37249e676ad4b7', '2025-12-23 14:28:31', NULL, NULL, NULL, '2025-11-23 08:58:31'),
(29, 51, '0f9423f704ba4fb3d228f8f1298f4ad2e27cde4bc4c2663944f469484924ad21', '2025-12-25 11:02:35', NULL, NULL, NULL, '2025-11-25 05:32:35'),
(30, 55, 'f0276c72d47d6deafdb1c0985b333fc8959337b692a80c68d534b5a85f4b70fc', '2025-12-25 20:37:51', NULL, NULL, NULL, '2025-11-25 15:07:51'),
(31, 56, '654b33e1080aef1fa8e70b188068bce646d9e5dcf13b61a451fabd198a6d554c', '2025-12-25 23:45:57', NULL, NULL, NULL, '2025-11-25 18:15:57'),
(32, 58, 'b806babfd5a5cf0a9eadabfd5f880b4e3b3e7c7157db802a71b61b6657e68588', '2025-12-26 16:11:15', NULL, NULL, NULL, '2025-11-26 10:41:15'),
(33, 58, '2b001ece4abd886f3a3767977267bc34d9f047cb1c04386a202ef2ad14182d79', '2025-12-26 17:33:34', NULL, NULL, NULL, '2025-11-26 12:03:34'),
(34, 61, '7864026bc27ed29f0170697209f6d47dde31097bb74875eeb41b302a7960f929', '2025-12-27 15:37:44', NULL, NULL, NULL, '2025-11-27 10:07:44'),
(35, 63, '8d9dccec358cf513bcf9f07afc84e36730172636acb73ee52e16dc25aed5d6fa', '2025-12-28 12:42:00', NULL, NULL, NULL, '2025-11-28 07:12:00'),
(36, 65, '7a00650abec770ff222c5325f5583399e796cd266086472e38b2847e1a4b37ff', '2025-12-29 19:16:18', NULL, NULL, NULL, '2025-11-29 13:46:18'),
(37, 67, '190fae76df7c8ee0936c65badd1154b83b395b1e8a38df85494628a394178b8c', '2025-12-30 14:59:58', NULL, NULL, NULL, '2025-11-30 09:29:58'),
(38, 68, '27aca81b4186c339f874f9b7df610da7a1b01d1be2b1066e1a48e647a0d1f24e', '2025-12-30 15:15:27', NULL, NULL, NULL, '2025-11-30 09:45:27'),
(39, 70, '5d9fbc4381ae319d4b7c4ca20e69550c07625ac82373437c633f8effdcf9ec61', '2025-12-30 16:34:08', NULL, NULL, NULL, '2025-11-30 11:04:08'),
(40, 71, '01946522354035fa49bfeb41c763f8430c4580d6ece8dbc105eace3e13412f9d', '2025-12-30 16:42:05', NULL, NULL, NULL, '2025-11-30 11:12:05'),
(41, 73, '054089fad3d77dfb0c6a27baa2447a97ae8ffa017b076228b014dc0043c0c68c', '2025-12-30 17:25:06', NULL, NULL, NULL, '2025-11-30 11:55:06'),
(42, 74, 'b3292673205601fb6bc347e001b4ce005bc198353beec7235405223115fdedb2', '2025-12-30 17:35:35', NULL, NULL, NULL, '2025-11-30 12:05:35'),
(43, 76, '1f34865fb62bc59d4a557b5e91e4387fc3d0d5293ab7fb57e3aa0ce2cb44d0cc', '2025-12-30 17:55:58', NULL, NULL, NULL, '2025-11-30 12:25:58'),
(44, 79, 'dde941c2fd88896eed9154a5a398f50e0ed87512011a42ae3808d21b7bb3b264', '2025-12-30 19:20:29', NULL, NULL, NULL, '2025-11-30 13:50:29'),
(45, 80, 'a5a2456772a63215caae75c25f452667919ff3dea4ae8c8d914d67cf6043b8ae', '2025-12-30 20:07:40', NULL, NULL, NULL, '2025-11-30 14:37:40'),
(47, 83, '79e6d2844a1c50e8b6cf1298b8e2797532f4eb16caba7ab491ee01be13280439', '2025-12-30 21:38:01', NULL, NULL, NULL, '2025-11-30 16:08:01'),
(49, 84, '02d5021896b41c0aa916e3bc35500db368883c5b2a8c6fcb3719732cf9f0eae7', '2025-12-30 22:38:01', NULL, NULL, NULL, '2025-11-30 17:08:01'),
(50, 85, '2f4e56c9f1002823df942f054d2e1483f6535ac84ca46e6699d0ffb8d75d9989', '2025-12-30 22:46:04', NULL, NULL, NULL, '2025-11-30 17:16:04'),
(51, 87, '46defda8000508707d03282c54a8cc5163309dd142fda76fcc95aef0dcbf654e', '2025-12-30 23:30:10', NULL, NULL, NULL, '2025-11-30 18:00:10'),
(52, 93, 'd0f43edfa268d7465024fe1dfa44e73cab7f0cb8e0adcf893b746c4b9cf08662', '2025-12-31 03:54:14', NULL, NULL, NULL, '2025-11-30 22:24:14'),
(53, 95, '57a44005a5912ee10fea62bf5a2f57251e31e7db31457a252340899fc7bd9db3', '2025-12-31 04:37:23', NULL, NULL, NULL, '2025-11-30 23:07:23'),
(54, 97, '282994b4ec91e480b9309f5253f5126920b7b64e5a6973712b4a40d268004012', '2025-12-31 08:11:35', NULL, NULL, NULL, '2025-12-01 02:41:35'),
(55, 100, '4e5601fa427cc54dc525d6f54797654ddcfa5b1025c4fcf33884ee14f4656bc9', '2025-12-31 10:05:22', NULL, NULL, NULL, '2025-12-01 04:35:22'),
(56, 104, '6c8652bc47ec121b325f533df9d4d8c277cbe56c1647e2e2d256e941dfe30a52', '2025-12-31 15:23:33', NULL, NULL, NULL, '2025-12-01 09:53:33'),
(57, 105, 'bec2accc1fc20b49c098ab0a75f965499cd6864e7e49aabf4a3ecfb1b5160304', '2025-12-31 16:43:56', NULL, NULL, NULL, '2025-12-01 11:13:56'),
(58, 108, '2cb7d6e0d84225b998eeda5a675c9397c105cc446a4c5762c1036bbaf8cbb358', '2025-12-31 19:13:06', NULL, NULL, NULL, '2025-12-01 13:43:06'),
(59, 112, '333a49078fb4bd19b7e74e4d359c8b1ae502101b699aa934fd5e6e88196836be', '2025-12-31 22:23:59', NULL, NULL, NULL, '2025-12-01 16:53:59'),
(60, 113, 'ac00290f4094a9228f4c27255feee8cb3339fe8f2ba9ca1d56046976386e6ab9', '2026-01-01 00:30:57', NULL, NULL, NULL, '2025-12-01 19:00:57'),
(61, 115, 'ac2460a0ad4077d3d5304e95247a3a7e27ce5c1b120f0f6c5f5a096dca33ef3e', '2026-01-01 01:21:04', NULL, NULL, NULL, '2025-12-01 19:51:04'),
(62, 117, '6d5d291c95cb4e7bfc2dbbc061e165fc0262c2908b5b55f899875d36a3bc3ec6', '2026-01-01 09:33:37', NULL, NULL, NULL, '2025-12-02 04:03:37'),
(63, 110, '76502e0d0aac917031ae913751b7d6d7ce46a604db2c4b4ee596b449b6e7a284', '2026-01-01 16:59:35', NULL, NULL, NULL, '2025-12-02 11:29:35'),
(64, 126, 'c242a2d0feedd097efaca665642e90c15093e96de72f7fbd7cfc11d86e86262c', '2026-01-01 20:37:36', NULL, NULL, NULL, '2025-12-02 15:07:36'),
(65, 131, '60103db1367af9185a26053f5c2531afc13bfc05609ef66e3c2eb3c6794f6834', '2026-01-02 09:11:28', NULL, NULL, NULL, '2025-12-03 03:41:28'),
(66, 133, '5b7bb33555f2b39378e015f77d1261009ce0638c2af46c3aec4bf6071d04c41f', '2026-01-02 19:23:55', NULL, NULL, NULL, '2025-12-03 13:53:55'),
(67, 136, 'c941c2cd63690cd2a7ee492ef5ebb902593f91bf6db66192e9cd5683c175b686', '2026-01-03 09:51:00', NULL, NULL, NULL, '2025-12-04 04:21:00'),
(68, 138, '4a77808832dc8e7243aa50c383ee8138413fd9e618cf66452d8c74732ab6ad9b', '2026-01-03 12:26:06', NULL, NULL, NULL, '2025-12-04 06:56:06'),
(69, 139, '22b0099ae4eb5eb86493b134f96db9de547c4de74182b26afcae3122456bea5e', '2026-01-04 01:10:01', NULL, NULL, NULL, '2025-12-04 19:40:01'),
(70, 141, 'f7190d492935c01975febe28b9f71ea93467a3dab257ac5d76d6e3803dc78d3d', '2026-01-04 13:17:43', NULL, NULL, NULL, '2025-12-05 07:47:43'),
(71, 66, '281bf53ba8a9c1860d1d8f6a09db7c96af716ab4b186a343244343c40aa72e67', '2026-01-06 12:44:29', NULL, NULL, NULL, '2025-12-07 07:14:29'),
(72, 152, 'e3ccc337623284e8ebe62a851a6b470906f8609d5aea7c6f4990cf8cf0518bed', '2026-01-07 22:10:42', NULL, NULL, NULL, '2025-12-08 16:40:42'),
(73, 154, '5cba4d89246fe83d23b2ad2e1ff3705f700535345125d5b24a060a18f1fd806c', '2026-01-08 10:13:39', NULL, NULL, NULL, '2025-12-09 04:43:39'),
(74, 157, '3c4c4e4c2cfd1fb44453057112bd2c4a1b17f0d81c29fe30f838d988b842743e', '2026-01-09 15:53:22', NULL, NULL, NULL, '2025-12-10 10:23:22'),
(75, 161, 'dcd50090ae2484248506885b384af6da7668e0e1419ce7b48d803c3c922d5a86', '2026-01-10 21:55:23', NULL, NULL, NULL, '2025-12-11 16:25:23'),
(76, 84, '080e753399b3cfa9ea27043f1fd1636e2afbd744bc71019a978930749c01ef02', '2026-01-10 23:57:32', NULL, NULL, NULL, '2025-12-11 18:27:32'),
(77, 163, 'f8b7f02390c6acac60e06e76411a6742990c9a025b0150dd9a0afde5f55a8563', '2026-01-11 19:23:27', NULL, NULL, NULL, '2025-12-12 13:53:27'),
(78, 164, '8693177b527132d175b875ac7dd1d5551de46160999441a8ae23323096bf1182', '2026-01-11 22:56:24', NULL, NULL, NULL, '2025-12-12 17:26:24'),
(79, 164, 'ffbc1017e2b8952a273b5c81c1de3a1fdedf0102c15842c53711e7e6642a8d43', '2026-01-12 17:47:30', NULL, NULL, NULL, '2025-12-13 12:17:30'),
(80, 167, '361342c4d7026a5547d0a1c4aa999a2b0e1fb27c7239cd4c67ae69b886db2ca2', '2026-01-13 13:47:21', NULL, NULL, NULL, '2025-12-14 08:17:21'),
(81, 168, '216f9b63f5f28eecf0404838e87eea32b55f0d0d329f5fbe8a77a589abe55f33', '2026-01-13 19:06:17', NULL, NULL, NULL, '2025-12-14 13:36:17'),
(82, 109, '2d6d1091e3209745f91c88dffafba00b3b5b8a509313f9ae923d92605c94e4c1', '2026-01-16 13:52:16', NULL, NULL, NULL, '2025-12-17 08:22:16'),
(83, 109, 'f0d0ac076bf02ae72baac33bd2cdf88a0b9abf14583ad64daa9952faa43e040c', '2026-01-16 15:16:05', NULL, NULL, NULL, '2025-12-17 09:46:05'),
(84, 173, '1a3b78170262c4273317a67e411b8a82a89d2e10f392a92efe4038dc485657fe', '2026-01-17 19:50:38', NULL, NULL, NULL, '2025-12-18 14:20:38'),
(85, 109, '419e05a3d9b00182f1f29c43d848c680e5e6e276055ff76ed6f94e41c6c03ce9', '2026-01-18 20:54:15', NULL, NULL, NULL, '2025-12-19 15:24:15'),
(86, 139, '4c7f66a2a129c88e5ce25d5c409df960da38265a06bf01d924598b4fd1afb423', '2026-01-20 17:19:25', NULL, NULL, NULL, '2025-12-21 11:49:25'),
(87, 164, 'ae7f28f8488c48baa99cce04ea4e78d4d0df4df1cb0f2974887a47fd8e822f96', '2026-01-21 14:30:52', NULL, NULL, NULL, '2025-12-22 09:00:52'),
(88, 176, '2d85ac7473e62ed84c82a5e20608c55398a8c0cf4ba04fdbf1d1209a292226b3', '2026-01-21 21:00:34', NULL, NULL, NULL, '2025-12-22 15:30:34'),
(89, 27, '05a561a9847e24beb4a3c5be7b5d2025459318599334270d29bbad28d0692059', '2026-01-22 12:06:17', NULL, NULL, NULL, '2025-12-23 06:36:17'),
(90, 177, '0ac4ad00b7c5cac0f10091216ec1e8ea3038672d10ab2fee7c13dfae0195ffad', '2026-01-22 21:22:35', NULL, NULL, NULL, '2025-12-23 15:52:35'),
(91, 178, 'b1968c3652aa91f76c91e378afe9f7999b85b365e5b2264a17b5b04eafaf88a4', '2026-01-23 16:31:36', NULL, NULL, NULL, '2025-12-24 11:01:36'),
(92, 179, '2b5bbde1f8c50569d1f1ab32ce90dd3479be397eacdcc98f79d0857a561f1cf7', '2026-01-24 12:11:36', NULL, NULL, NULL, '2025-12-25 06:41:36'),
(93, 183, '3fc6ccfaa4773ee56ca16653824142fbaec39223aa45c9e33458a98b948e9428', '2026-01-25 19:16:40', NULL, NULL, NULL, '2025-12-26 13:46:40'),
(94, 186, '6d14a1e419622345c993739ad037260a7ab204366039efebe5267d1a8866021c', '2026-01-28 11:49:24', NULL, NULL, NULL, '2025-12-29 06:19:24'),
(95, 152, 'ec51bfd35249914d25a883c3051670772121b78686f3e7c8f560af1fbeb483b9', '2026-01-28 15:37:30', NULL, NULL, NULL, '2025-12-29 10:07:30'),
(96, 187, 'b5812b3ed2ed90da1f34f255c1ab69845eeca1281e2c5e2d6a38e64c6b496c21', '2026-01-28 15:50:56', NULL, NULL, NULL, '2025-12-29 10:20:56'),
(97, 201, '532431ae7383a653f1c6c0f8013573d4618670eecf7e2f8f5aad3c206c7ce670', '2026-02-04 18:42:05', NULL, NULL, NULL, '2026-01-05 13:12:05'),
(98, 204, '9b418c9c9ce85f47316f7f38a4f08bc1121541a5af7e0c7b0ae1fc49f5a233fe', '2026-02-06 10:06:54', NULL, NULL, NULL, '2026-01-07 04:36:54'),
(99, 207, '73e7064548078c2458b47371b51b7dfe1fd652f45e560134bfd40fbe1701dc3d', '2026-02-07 02:19:15', NULL, NULL, NULL, '2026-01-07 20:49:15'),
(100, 27, '82182108efcecda3e51e833388ca1ba796c5b8c1bd7d35e7a1b6f7ab2ee5f9ec', '2026-02-07 16:19:29', NULL, NULL, NULL, '2026-01-08 10:49:29'),
(101, 27, '63e7550e98b5306c309c1138988727cf30286e90437e53fdc573ca5ee28b7717', '2026-02-07 16:19:39', NULL, NULL, NULL, '2026-01-08 10:49:39'),
(102, 27, '663d2c909a637332ba3f551131d59635b0b2af5539f1fbcf812d3f351d8fc0c3', '2026-02-07 16:19:45', NULL, NULL, NULL, '2026-01-08 10:49:45'),
(103, 27, 'd78790a8c038402e63be5c7abb0a8b86b00e4aff689ceb47e2366bf8db2e3527', '2026-02-07 16:19:52', NULL, NULL, NULL, '2026-01-08 10:49:52'),
(104, 27, '4a93118824d7b465786c6dc48ec41a6ef042af358a3e50a1dd83763d0ee3a94c', '2026-02-07 16:19:58', NULL, NULL, NULL, '2026-01-08 10:49:58'),
(105, 27, '0aa1b35d0b8ededd0ec3d3d5987ce62b545529b8a37c390e082bd7ce26c89642', '2026-02-07 16:20:05', NULL, NULL, NULL, '2026-01-08 10:50:05'),
(106, 27, 'e05389c65392abc144a63bb6112c264f7f03377555cb6c0eb77cd3268f876fe4', '2026-02-07 16:20:12', NULL, NULL, NULL, '2026-01-08 10:50:12'),
(107, 27, '0d7e84481b0bdd1f1ada3c97e895bc4ec850a7db163399560c1eb52a1e0182e6', '2026-02-07 16:20:19', NULL, NULL, NULL, '2026-01-08 10:50:19'),
(108, 27, '6ecd4e2e2fc9fd0e48cc19de9ca4d4d4b23815150415663270c9088d7fc65d4c', '2026-02-07 16:20:25', NULL, NULL, NULL, '2026-01-08 10:50:25'),
(109, 27, '05cad94a2b008a546c537d91411f3a534076b51cf40ed1c4d253651d4114cb06', '2026-02-07 16:20:32', NULL, NULL, NULL, '2026-01-08 10:50:32'),
(110, 27, '78045cda0c579c891b870d1a4704adfe38d5e07ec4ebbe177790575eb834e0c3', '2026-02-07 16:20:39', NULL, NULL, NULL, '2026-01-08 10:50:39'),
(111, 27, '6bfac0c88cf8486cf2c17c84fa6a655f36e915f3033d7fa9de554932a564a56f', '2026-02-07 16:20:45', NULL, NULL, NULL, '2026-01-08 10:50:45'),
(112, 27, '64d12188ee789ec1b42eb444c9e40ef387b59e4a8bfb0879969cf260fdf3a4f3', '2026-02-07 16:20:51', NULL, NULL, NULL, '2026-01-08 10:50:51'),
(113, 27, '911505c89ee9ac1487cde6a6a097f8d945119077920bfe339585a95fe8236870', '2026-02-07 16:20:58', NULL, NULL, NULL, '2026-01-08 10:50:58'),
(114, 27, 'd973c8e7672bb58de6263c5edeb2543424866e7d75b741a5223612487dc2722a', '2026-02-07 16:21:04', NULL, NULL, NULL, '2026-01-08 10:51:04'),
(115, 27, 'f461675a82746568fb5c3810adee7e9e95ccaacbc029021968feec5ca670c320', '2026-02-07 16:21:11', NULL, NULL, NULL, '2026-01-08 10:51:11'),
(116, 27, '65c7eeca476cf9a53b70a586d4cad6f9b9c0f5336ffdf289d669a023275a1221', '2026-02-07 16:21:18', NULL, NULL, NULL, '2026-01-08 10:51:18'),
(117, 27, 'd1b06e4a3a195f52ab026b9ef84e83c07161fa272d4807cfd99cd383e1ce7beb', '2026-02-07 16:21:24', NULL, NULL, NULL, '2026-01-08 10:51:24'),
(118, 27, '2f158e284dabdffe36c6f2df5f8c7ea195bcf375b084ac0c93095d85bbecef7a', '2026-02-07 16:21:31', NULL, NULL, NULL, '2026-01-08 10:51:31'),
(119, 27, '626014a022e6023bbc5401ed390033fd6520c0008ecd4517ee3c7102c2bc3775', '2026-02-07 16:21:37', NULL, NULL, NULL, '2026-01-08 10:51:37'),
(120, 27, '9b8d6646679d2eaecd697a24a2ec2c03bf8d2c4e5281025f0d2f5d198e16b932', '2026-02-07 16:21:43', NULL, NULL, NULL, '2026-01-08 10:51:43'),
(121, 27, '09f5cf29a118de04da09c4b6fb4aa63d2ed716a6a9bab77b16cda6befd5b03b2', '2026-02-07 16:21:50', NULL, NULL, NULL, '2026-01-08 10:51:50'),
(122, 27, '2a1ca9dafb32131ba418569ad1506e742a3317e7fc5b9b084ad7e23f107e2590', '2026-02-07 16:21:56', NULL, NULL, NULL, '2026-01-08 10:51:56'),
(123, 27, 'cdb1041ecb4d753ccb45aa5320e8ed2ebbd560e7ea9fd31e1031bf805c323a7e', '2026-02-07 16:22:02', NULL, NULL, NULL, '2026-01-08 10:52:02'),
(124, 27, 'd35b4a8f28319e65f2cc4d1db958b88ab0db8ea6677d31ad57787059826e4998', '2026-02-07 16:22:07', NULL, NULL, NULL, '2026-01-08 10:52:07'),
(125, 27, 'eb73713edda50f6d868dcd3b2ce1456bf3be889dcb65b8db4f8ca75cbf753961', '2026-02-07 16:22:12', NULL, NULL, NULL, '2026-01-08 10:52:12'),
(126, 27, 'd0e1a061cbbfe0cf87ce07fed10a67084d8dfb519f9c81fd2899415f63ec48be', '2026-02-07 16:22:17', NULL, NULL, NULL, '2026-01-08 10:52:17'),
(127, 27, '3e84cd7b90778e26d528cf9958ecc45f498822ff86dd13dc78253784d90fee91', '2026-02-07 16:22:22', NULL, NULL, NULL, '2026-01-08 10:52:22'),
(128, 27, '14b8e907fe730ab41770fc1719ceee19a5129c3fbd53da218d99234447ad3f3c', '2026-02-07 16:22:27', NULL, NULL, NULL, '2026-01-08 10:52:27'),
(129, 27, 'f5d581d7b9671142a9990497cc13007b6f06655f675411a72d179a77336ead1e', '2026-02-07 16:22:33', NULL, NULL, NULL, '2026-01-08 10:52:33'),
(130, 27, '18eaf54455950b67b0f090bd38003a663524c83cfec46b32999bdec57a363a9c', '2026-02-07 16:22:44', NULL, NULL, NULL, '2026-01-08 10:52:44'),
(131, 27, '6f3e02c9045dc685371824e69c1e1814f9c12fbfad9d78161e0916435de28af5', '2026-02-07 16:22:51', NULL, NULL, NULL, '2026-01-08 10:52:51'),
(132, 27, 'dc2b58bff3a283c3eaf4624055d6fbb869d581427c0346717fb52b560e3fcf13', '2026-02-07 16:22:57', NULL, NULL, NULL, '2026-01-08 10:52:57'),
(133, 27, 'f25bf2db9c20d6209f4d9eedd28e182b13afff5e3a4e33c4f524411d454d580c', '2026-02-07 16:23:03', NULL, NULL, NULL, '2026-01-08 10:53:03'),
(134, 27, 'b2b5fe57f65d15e4896d4874604e2c099a4f68d56b126c63501f4acadbb4c433', '2026-02-07 16:23:12', NULL, NULL, NULL, '2026-01-08 10:53:12'),
(135, 27, '19c290efaf3dd4e824e985acc531d34138f7a839fcbfb4c168b5e433567f712e', '2026-02-07 16:23:20', NULL, NULL, NULL, '2026-01-08 10:53:20'),
(136, 27, '0b5afe317511ca0e6e6e43b9347ac218d294975de3a4117fc5519388bd347497', '2026-02-07 16:24:44', NULL, NULL, NULL, '2026-01-08 10:54:44'),
(137, 27, '25dedd554b4cd495a15e53d45d5bbf7ac8cfe5434c4b28a01525f7622d2b76de', '2026-02-07 16:26:08', NULL, NULL, NULL, '2026-01-08 10:56:08'),
(138, 27, '3ab0ce17d428093ea1edb3d38a27ad6577e64043bc528cfe4fc96abb3377a0f5', '2026-02-07 16:26:23', NULL, NULL, NULL, '2026-01-08 10:56:23'),
(139, 27, '5019691d208adef851c11021de2e758c78bd955dbe07c5775f16389aa575526b', '2026-02-07 16:26:27', NULL, NULL, NULL, '2026-01-08 10:56:27'),
(140, 27, '5455900208ea484ffc0e73e5b1265935c8810ac936297926933165cbb2494d1a', '2026-02-07 16:26:35', NULL, NULL, NULL, '2026-01-08 10:56:35'),
(141, 27, 'b01f847843110a7acb314f01097f9299a5b325f53b71c1fc5be5d3e1b5371c9d', '2026-02-07 16:26:41', NULL, NULL, NULL, '2026-01-08 10:56:41'),
(142, 27, 'e301cc4fff2b43d5b29c550b361561c7c2c7ce15fede1977f9709e8fec398ccc', '2026-02-07 16:26:43', NULL, NULL, NULL, '2026-01-08 10:56:43'),
(143, 27, '9e694766ef49a8dd060fd1ad88344881354a4a3e655d82a1aba9c53c4f000660', '2026-02-07 16:26:52', NULL, NULL, NULL, '2026-01-08 10:56:52'),
(144, 27, 'a50cf0e39c6d125b1faef636edb934c12a3e88cbfbde3d6ab3cc25f96d4170bc', '2026-02-07 16:26:58', NULL, NULL, NULL, '2026-01-08 10:56:58'),
(145, 27, '9032d4a844f3a3a70d24aaec734ef5c7228e9c222f5bff4b86100b6ce2877236', '2026-02-07 16:27:00', NULL, NULL, NULL, '2026-01-08 10:57:00'),
(146, 27, '69d90aa100c9fef1d955208b26cc1d5289e9f540f5112ea391fb8ab3e0d0c404', '2026-02-07 16:27:09', NULL, NULL, NULL, '2026-01-08 10:57:09'),
(147, 27, '20ad1d21d65aa7ed5c986abbff0faf23fd98c088c1bf8e96f2921267217c24c1', '2026-02-07 16:27:16', NULL, NULL, NULL, '2026-01-08 10:57:16'),
(148, 27, 'e339331b036ec55189cbc9a76134ad126313658f957cb8a442a099d661a015c4', '2026-02-07 16:27:17', NULL, NULL, NULL, '2026-01-08 10:57:17'),
(149, 27, '5b335bc2c4ece2fe951ca174eead81fe8d496419bb7d63844ace8d586c026655', '2026-02-07 16:27:25', NULL, NULL, NULL, '2026-01-08 10:57:25'),
(150, 27, '1573efed66125f01c6956c423fa77b2d9e3b179ebbc20e9044b4f86b0686d3f0', '2026-02-07 16:27:34', NULL, NULL, NULL, '2026-01-08 10:57:34'),
(151, 27, '1c6fa406a8a931b380a95fa8c1ff277197fb10f7cff8959b770baecaf539c418', '2026-02-07 16:27:34', NULL, NULL, NULL, '2026-01-08 10:57:34'),
(152, 27, 'dfc5f16db519fe2713bc7cd74b3bcdffa4c7657af60a49d469b4d956836d32e1', '2026-02-07 16:27:40', NULL, NULL, NULL, '2026-01-08 10:57:40'),
(153, 27, '0b36e6d420abe706ee557218691e26dc3bcadc1ae22e941be839e51f98bed24d', '2026-02-07 16:27:52', NULL, NULL, NULL, '2026-01-08 10:57:52'),
(154, 27, 'a327669222a5a7c52822c1609ee7397511f36c5b46c74ea809953f16a276a451', '2026-02-07 16:27:56', NULL, NULL, NULL, '2026-01-08 10:57:56'),
(155, 27, '1f245476e85724bcd445af0b6009be0e49d75c57497edf828c3c0b37424f9e2a', '2026-02-07 16:28:02', NULL, NULL, NULL, '2026-01-08 10:58:02'),
(156, 27, '8b0b94e5700caa9364e1feb47b2fd7fa14d801c982e3312320d0fd0afbdfcf23', '2026-02-07 16:28:06', NULL, NULL, NULL, '2026-01-08 10:58:06'),
(157, 27, '2b16517314075c57cf726f190946ff45413743e9ee8e1dbddeab25bad2c246b6', '2026-02-07 16:28:13', NULL, NULL, NULL, '2026-01-08 10:58:13'),
(158, 27, '20f6e8faf9bca290e760cb71a3e78daf0e1b01a4979464a0e630de185ea99138', '2026-02-07 16:28:18', NULL, NULL, NULL, '2026-01-08 10:58:18'),
(159, 27, 'dae9f06836662d8850926a4deda8de8512fed33ec149d3fc49a8da00013aa645', '2026-02-07 16:28:29', NULL, NULL, NULL, '2026-01-08 10:58:29'),
(160, 27, 'b0490d86014fca06d08a5f1ad7ba12689b9fead2c505bc27bbc2fee9a5978bce', '2026-02-07 16:28:34', NULL, NULL, NULL, '2026-01-08 10:58:34'),
(161, 27, '6082d8465698c61830b49c3f1f628dfe36fc1064723aaa412386438e919f7da7', '2026-02-07 16:28:38', NULL, NULL, NULL, '2026-01-08 10:58:38'),
(162, 27, 'd7dac4ba250261ff92626d29e1fefd622bcfdec96a8a0037720399306ecfc263', '2026-02-07 16:28:46', NULL, NULL, NULL, '2026-01-08 10:58:46'),
(163, 27, '66e5dc1242906032ba93ed3cddac9230c91ca3e57f1e03b8c9720b0b73bb5cf6', '2026-02-07 16:29:02', NULL, NULL, NULL, '2026-01-08 10:59:02'),
(164, 27, '630bd462e52aa446ed3325626e7e84b137469e0f53371ed66bbc5cdc30a5bf02', '2026-02-07 16:29:20', NULL, NULL, NULL, '2026-01-08 10:59:20'),
(165, 27, 'f378663a5631b19a55d480013811af6ce20dea5708094e6faacef85a2946f1f2', '2026-02-07 16:29:51', NULL, NULL, NULL, '2026-01-08 10:59:51'),
(166, 27, '0c34fdba4e743fe188cc6d5f322fbbe68cdf5bd36e3a54bbf1133726ee476538', '2026-02-07 16:30:08', NULL, NULL, NULL, '2026-01-08 11:00:08'),
(167, 27, 'a847263377fc9c6b74ad6fc1dfe0933a550c8ee811d77fe606d7685a9e6d0686', '2026-02-07 16:30:26', NULL, NULL, NULL, '2026-01-08 11:00:26'),
(168, 27, 'e5f6d1ec013e6c937259792ec8c46697a551c0cd026a8ff4ae4b3eff3102d5ca', '2026-02-07 16:30:44', NULL, NULL, NULL, '2026-01-08 11:00:44'),
(169, 27, '220b30945768d2274099bd05f93bbe24822758c820957e1a33733d94d19f9b06', '2026-02-07 16:30:58', NULL, NULL, NULL, '2026-01-08 11:00:58'),
(170, 27, '744dd19258b25225460479e4a8b88cd2205a0aeb3a0be2c90e550bd17abe9b75', '2026-02-07 16:31:13', NULL, NULL, NULL, '2026-01-08 11:01:13'),
(171, 27, '6c3580ef1864aade2daa46ae27a36d215417bb4e226fdd1420e575545d7c79f8', '2026-02-07 16:31:28', NULL, NULL, NULL, '2026-01-08 11:01:28'),
(172, 27, 'bda7d467023961292d8f6ff59a7d7e62fdbbb5cd31909cea06da841fd10c4a81', '2026-02-07 16:31:43', NULL, NULL, NULL, '2026-01-08 11:01:43'),
(173, 27, '41c36f1dcad07756657545670b5fb8b7a4a549f5d13b426a78f99ce8a197ae0e', '2026-02-07 16:31:57', NULL, NULL, NULL, '2026-01-08 11:01:57'),
(174, 27, '02bbe2d32902d4da12c5228654da8a8238c7ced146949bc1c399c0fe8c73522d', '2026-02-07 16:32:11', NULL, NULL, NULL, '2026-01-08 11:02:11'),
(175, 27, '84b5f0aa1fa91e8f7cb1964db52fabc6030cd247f090b1d90d6509d0313f50b8', '2026-02-07 16:32:24', NULL, NULL, NULL, '2026-01-08 11:02:24'),
(176, 27, '9cc138c8ac3b94b15ccd18e7e0cb11ffa509128265f8da20872706ecba35ee74', '2026-02-07 16:32:38', NULL, NULL, NULL, '2026-01-08 11:02:38'),
(177, 27, '8fb5fa5716d6e9ce832ddeacc5c0fa9013ec992265764e678b87839e4fc21f7a', '2026-02-07 16:32:52', NULL, NULL, NULL, '2026-01-08 11:02:52'),
(178, 27, '8d394b7d1037fa258f0cc5b9f9366a39dc6195e9d1a21d6bc0e6164e7d7026bb', '2026-02-07 16:33:05', NULL, NULL, NULL, '2026-01-08 11:03:05'),
(179, 27, 'bfa5d2f605bdea6f4217f8ac4e8c7f681929e67063f0a7de4cc09d03ccf95b99', '2026-02-07 16:33:19', NULL, NULL, NULL, '2026-01-08 11:03:19'),
(180, 27, '1a66a06e588df21392e259da807bdc5da1d3d257e85c142d7c93bf498906612f', '2026-02-07 16:33:26', NULL, NULL, NULL, '2026-01-08 11:03:26'),
(181, 27, 'a70cf5dcd8fb49067b9600b95071cee503029ed3b926b7c4658286c6f7409e33', '2026-02-07 16:33:33', NULL, NULL, NULL, '2026-01-08 11:03:33'),
(182, 27, '2e4867f603e7578b5080f77f262eae5a3e85e308f5e49d01ea2728bd2451b111', '2026-02-07 16:33:47', NULL, NULL, NULL, '2026-01-08 11:03:47'),
(183, 27, '480f275ab5934e73fe24ce941a2cefd30923876999b9e34cb76795e02075aafb', '2026-02-07 16:34:02', NULL, NULL, NULL, '2026-01-08 11:04:02'),
(184, 27, '363606cd87dc84aa143a7ec1e6d683bc94e1f8157abee7751573d6c28c930bc6', '2026-02-07 16:34:15', NULL, NULL, NULL, '2026-01-08 11:04:15'),
(185, 27, '6d60f8fb53b09bde8e5fabd39f0906331616868a8fae7d40c4687a04fa71cccc', '2026-02-07 16:34:28', NULL, NULL, NULL, '2026-01-08 11:04:28'),
(186, 27, 'd036cb391864dc08b75213d7d787937bfdf191dd80a019641648e1777c0a2f59', '2026-02-07 16:34:41', NULL, NULL, NULL, '2026-01-08 11:04:41'),
(187, 27, '46c80aae0826250bc8a37139542cd184921b6c6225aa481adbd43fb84d653135', '2026-02-07 16:34:53', NULL, NULL, NULL, '2026-01-08 11:04:53'),
(188, 27, '0f02a0865c374390980d527cfb376e939726472494219360af4885f9aa140062', '2026-02-07 16:35:07', NULL, NULL, NULL, '2026-01-08 11:05:07'),
(189, 27, 'bd8e25b142e26d90550b0abd8add69957b0c33f8254f78d1ef4c0c54933ac498', '2026-02-07 16:35:19', NULL, NULL, NULL, '2026-01-08 11:05:19'),
(190, 27, '37ea37060f1254ff2f961507b77fd2a21739ccca9fd95c29c154c6a16141fc59', '2026-02-07 16:35:22', NULL, NULL, NULL, '2026-01-08 11:05:22'),
(191, 27, 'cf4602cf804d9640da943c4149ce85a2460ab06d8621db14eaaac1f50f5430dd', '2026-02-07 16:35:35', NULL, NULL, NULL, '2026-01-08 11:05:35'),
(192, 27, '54a4040b6d3f90773a3efb857921b16e6ce14739eddbd5f856dffad74ac85d26', '2026-02-07 16:35:50', NULL, NULL, NULL, '2026-01-08 11:05:50'),
(193, 27, '988165ce6f7ee1a524252c696c970ae22bdbb2f42eead03184d1ed9dec1c400d', '2026-02-07 16:36:06', NULL, NULL, NULL, '2026-01-08 11:06:06'),
(194, 27, 'c0602bf2846cc411d16e1c1487a1f243a021907531608ce352de102f4aaa9ae6', '2026-02-07 16:36:21', NULL, NULL, NULL, '2026-01-08 11:06:21'),
(195, 27, '303bcbc1d0cb0597dde0addef813e69b8302ee3ed5ebd794a3eb99ade15e8d43', '2026-02-07 16:36:37', NULL, NULL, NULL, '2026-01-08 11:06:37'),
(196, 27, 'd8c3f9a2e6b053e03fbe9a45e27f238ea002ea944f861437f5593aa766d45afe', '2026-02-07 16:36:50', NULL, NULL, NULL, '2026-01-08 11:06:50'),
(197, 27, 'e6eb6554112f390f11bc162f57e40f682f02eeae2aabc9222785f5c2e9eb82cb', '2026-02-07 16:37:03', NULL, NULL, NULL, '2026-01-08 11:07:03'),
(198, 27, '612689379030b3a769864c631db5216ca9d02946f60bcdecfd569581aca790ab', '2026-02-07 16:37:16', NULL, NULL, NULL, '2026-01-08 11:07:16'),
(199, 27, 'cca10ffe11b75f3b14d9eac062bb35e3975a6a7ec43d96d52ab13fd403f68779', '2026-02-07 16:37:33', NULL, NULL, NULL, '2026-01-08 11:07:33'),
(200, 27, '6393364b254c3a23d3f2e7b5437ef1dfd3b5d3229162dc290d84e7856be1c1e1', '2026-02-07 16:37:48', NULL, NULL, NULL, '2026-01-08 11:07:48'),
(201, 27, '661c9a306b3bb100f33824eab6b6a1c60e1bd58a089534fe7a1a0932d3b339a4', '2026-02-07 16:38:03', NULL, NULL, NULL, '2026-01-08 11:08:03'),
(202, 27, '455cf4c0c64ea845198f0d8a5c7dc898eab72b209bde94dfc6be64dfb1eb2323', '2026-02-07 16:38:17', NULL, NULL, NULL, '2026-01-08 11:08:17'),
(203, 27, '6c01f0389e8dbf85ac59299bafeeb7a85f1537f49e89df33c83f77db9b2b7aa6', '2026-02-07 16:38:30', NULL, NULL, NULL, '2026-01-08 11:08:30'),
(204, 27, 'ec1b10dae32fe79fec41c578fec44022fac2082fc233c332be879225f7ea8340', '2026-02-07 16:38:32', NULL, NULL, NULL, '2026-01-08 11:08:32'),
(205, 27, '6b0f3a28cdc06ecdfacb054e23367d9b24413c2f7042c270cec868c70ae32366', '2026-02-07 16:38:40', NULL, NULL, NULL, '2026-01-08 11:08:40'),
(206, 27, '9fde9e10a119433005ccb60361c51f159dc76b17aa59cfef6430f27718712fb1', '2026-02-07 16:38:45', NULL, NULL, NULL, '2026-01-08 11:08:45'),
(207, 27, 'feff8238bb175d11d0c5ae9e38f0446f7a5967b978d1c6a7a428c634f32efcee', '2026-02-07 16:38:46', NULL, NULL, NULL, '2026-01-08 11:08:46'),
(208, 27, 'a4e220dbaf9e197ecfe64c8d12cb250a3a97758850d137ffabfc4c90ae2124bb', '2026-02-07 16:38:54', NULL, NULL, NULL, '2026-01-08 11:08:54'),
(209, 27, '54f1ccf66c38a1c1dc957544f29ad9046e098807199f020524094932b52a7f3b', '2026-02-07 16:38:55', NULL, NULL, NULL, '2026-01-08 11:08:55'),
(210, 27, '4ffa9c9bad6b3f71b7d1a07c2b819f3225a88bab644e43055c2d3077160964ea', '2026-02-07 16:38:59', NULL, NULL, NULL, '2026-01-08 11:08:59'),
(211, 27, 'ad7397658f870e8364f60fb9931d4d56094243f6ba270b08e6bdfed5bb8961a1', '2026-02-07 16:39:06', NULL, NULL, NULL, '2026-01-08 11:09:06'),
(212, 27, 'd6160749f5aa3ae0ac67b732c2dc7584b9e60fb47fe36149d6e5c6c2d23a0079', '2026-02-07 16:39:08', NULL, NULL, NULL, '2026-01-08 11:09:08'),
(213, 27, 'be74d2a40253876ff9869c81bec779b27695e5f8fbba702f845b1fa779ac86a9', '2026-02-07 16:39:13', NULL, NULL, NULL, '2026-01-08 11:09:13'),
(214, 27, '6ebae11c6edc1c00a955dde5c4bc7753edfddb5fcdf0ad522778be65eaa13e17', '2026-02-07 16:39:19', NULL, NULL, NULL, '2026-01-08 11:09:19'),
(215, 27, 'a9aa824d69c2f8c3f013efb6ff79f77fd149f10a1a8e3f9ecd9e51b94f8b154d', '2026-02-07 16:39:21', NULL, NULL, NULL, '2026-01-08 11:09:21'),
(216, 27, 'ec1767c991fa870bc877955d8df9d79dd7055fabc5c10cab3d00c2c162b6fb23', '2026-02-07 16:39:27', NULL, NULL, NULL, '2026-01-08 11:09:27'),
(217, 27, 'c931bde0a2ee7d973e05e1b05d9467b0503bdca57a751f59047a60c7aadbd5fa', '2026-02-07 16:39:32', NULL, NULL, NULL, '2026-01-08 11:09:32'),
(218, 27, 'd4836ad3ce1d6f9ae6a4fb37747259080edf66a782800a6792aafbdfb0f42b9c', '2026-02-07 16:39:34', NULL, NULL, NULL, '2026-01-08 11:09:34'),
(219, 27, '59dfbd6d2e099eb932298cb1f360359fa43dc5b6206fbbf9d86eb29f9b17035d', '2026-02-07 16:39:39', NULL, NULL, NULL, '2026-01-08 11:09:39'),
(220, 27, '52d2286ce1574f6565c1cd5811e00eb6cd8b9bf78a755ada521ab7cbb9e46647', '2026-02-07 16:39:42', NULL, NULL, NULL, '2026-01-08 11:09:42'),
(221, 27, '595dffbb59a84b1339967737098d0691155c410680c64df98fa4307aefa04f61', '2026-02-07 16:39:44', NULL, NULL, NULL, '2026-01-08 11:09:44'),
(222, 27, '58865864275d283bff818de4635c49abb632c1bbb4d2672f3a123eb15ab17911', '2026-02-07 16:39:46', NULL, NULL, NULL, '2026-01-08 11:09:46'),
(223, 27, '7d86be118f2516c7aa7972a2fd0379a9d7aa5389992239c897d40cd41aba84d6', '2026-02-07 16:39:51', NULL, NULL, NULL, '2026-01-08 11:09:51'),
(224, 27, 'f4826189afb61de7f99319f581e112092899a1c6ce0b7ec59f7e4abc887abce5', '2026-02-07 16:39:53', NULL, NULL, NULL, '2026-01-08 11:09:53'),
(225, 27, 'ce4da30745d68464b16c640a464c164b48d6eb128052cc9b32645f283ce0d31e', '2026-02-07 16:39:56', NULL, NULL, NULL, '2026-01-08 11:09:56'),
(226, 27, '2c34d2b12b6dd10a78be9ee6139febfec01162129aa225d63946f34bcf9c1d36', '2026-02-07 16:39:58', NULL, NULL, NULL, '2026-01-08 11:09:58'),
(227, 27, 'ff6f8696728bb9a8b0878fa721bb8def383e157d55ad204aa708404d334f2de3', '2026-02-07 16:40:06', NULL, NULL, NULL, '2026-01-08 11:10:06'),
(228, 27, 'b9da5c93acc04e9e4f34e50339559cbb351ad01a70dbada55d0e61b53fcb25ab', '2026-02-07 16:40:09', NULL, NULL, NULL, '2026-01-08 11:10:09'),
(229, 27, 'b06d9f73c79c77c49070ef9aa8f1e540fbd42964833a8a181ec2e0ade22050b4', '2026-02-07 16:40:12', NULL, NULL, NULL, '2026-01-08 11:10:12'),
(230, 27, '28ed24065a4fd4233561967248a6c0c18d2aa7b3bccb328e26d8bb4d88259b8c', '2026-02-07 16:40:14', NULL, NULL, NULL, '2026-01-08 11:10:14'),
(231, 27, '986d7e031a5b4c8db801b01f45920f3bc01065decb178eb355f6659ec6591998', '2026-02-07 16:40:25', NULL, NULL, NULL, '2026-01-08 11:10:25'),
(232, 27, 'e6925f2b2fb226e280f65bf3bb26ffa467361c00b9f6b47acf2ca49f185d1c0b', '2026-02-07 16:40:26', NULL, NULL, NULL, '2026-01-08 11:10:26'),
(233, 27, 'f095342bd92a86b08e625b798aab9f49a91b0a675fb854fed1ccd65b0936b309', '2026-02-07 16:40:27', NULL, NULL, NULL, '2026-01-08 11:10:27'),
(234, 27, '44e6f40ec86cd7d84ec22effaad52f89e0facf93b29e9ba2f6a53a8375470d8b', '2026-02-07 16:40:29', NULL, NULL, NULL, '2026-01-08 11:10:29'),
(235, 27, '8920f6f3f4a1cd1e204db2410f510c068acd1f07c5df396997787fea1d6ad4d5', '2026-02-07 16:40:40', NULL, NULL, NULL, '2026-01-08 11:10:40'),
(236, 27, 'e345145b0c9e08b4ff0a4695508b1e85229cc658f05c6a4c7b8c1cce6d7c5a52', '2026-02-07 16:40:44', NULL, NULL, NULL, '2026-01-08 11:10:44'),
(237, 27, '82589eefa1e39ef5ba634ecb981dd2af9e503cde1550cead8deb6c551821429a', '2026-02-07 16:40:47', NULL, NULL, NULL, '2026-01-08 11:10:47'),
(238, 27, '387324a8db042da1823ebd85f9a16954755e558c8caf7649e936a9a6b9fa5367', '2026-02-07 16:40:55', NULL, NULL, NULL, '2026-01-08 11:10:55'),
(239, 27, '76be8beaf03c21e0e219e0893b95ddab6f5f4f5395fd1f333512f1784ba5e376', '2026-02-07 16:41:00', NULL, NULL, NULL, '2026-01-08 11:11:00'),
(240, 27, 'b1fc355838370fffde6d1b84cbcaed608a9dc5c9de1e688f59d38e3c55ad2fa4', '2026-02-07 16:41:00', NULL, NULL, NULL, '2026-01-08 11:11:00'),
(241, 27, 'cde28b60b6f8e009506b4b02af350f50dbc3a175b83edd743c0627b4fcaf8583', '2026-02-07 16:41:01', NULL, NULL, NULL, '2026-01-08 11:11:01'),
(242, 27, '489cc53e0c0aed93d7801f2af607b8ba7ab9f394bb04e95a3b8cd216b0242c21', '2026-02-07 16:41:10', NULL, NULL, NULL, '2026-01-08 11:11:10'),
(243, 27, '1c79854c2595d9d17f3d8d741c864993977a7003538eb907b05a2ef38a82e4ef', '2026-02-07 16:41:18', NULL, NULL, NULL, '2026-01-08 11:11:18'),
(244, 27, '3a1b42dc15050192607349dc5b28d73ecdfe64d45047cc7afc07b9e04a14ba0f', '2026-02-07 16:41:19', NULL, NULL, NULL, '2026-01-08 11:11:19'),
(245, 27, '30d5cd39eeb5cb07e755967d2be2ccf5ec5af4b9c3b26a27548150f4dc81c8f3', '2026-02-07 16:41:25', NULL, NULL, NULL, '2026-01-08 11:11:25'),
(246, 27, 'da22be1253065aae70257d991d21b397d1a30ba4f7893e16538eb0dc5656f94d', '2026-02-07 16:41:30', NULL, NULL, NULL, '2026-01-08 11:11:30'),
(247, 27, 'aa288fbe8800825a6fc11d320201b0cd9bdf80dddb482d786237cff880da3ae1', '2026-02-07 16:41:33', NULL, NULL, NULL, '2026-01-08 11:11:33'),
(248, 27, '07ca21ff73268fdd9b994ce1e9ebfc5ebd0dcebe4fc9218983d099f8901e6436', '2026-02-07 16:41:34', NULL, NULL, NULL, '2026-01-08 11:11:34'),
(249, 27, '6f950de44dc8e8c0e4ff86e5d197be99330348936a9cd72b4ffea9bd5837037e', '2026-02-07 16:41:41', NULL, NULL, NULL, '2026-01-08 11:11:41'),
(250, 27, 'dcdac6c1ceaf66abf2dbbd9dc8645ae0a0c669c1c967eb40794787b0422fc208', '2026-02-07 16:41:43', NULL, NULL, NULL, '2026-01-08 11:11:43'),
(251, 27, 'abcdfb88388066e52f43d0e0fa5db82def8f719d756c4c198f44be56c61bd6c6', '2026-02-07 16:41:45', NULL, NULL, NULL, '2026-01-08 11:11:45'),
(252, 27, '6a00c59b59d7ccbaecfb00bf207bf5fa3886bef73f7cf861ddbe58f0ac0e59a1', '2026-02-07 16:41:50', NULL, NULL, NULL, '2026-01-08 11:11:50'),
(253, 27, '3813992999e4e9b2f647651a65a5ac93c53c363be20743a9809008ec9506bc2b', '2026-02-07 16:41:50', NULL, NULL, NULL, '2026-01-08 11:11:50'),
(254, 27, '17c655a43fae51b26df19c711fabcbc2d6540937feb21eee99957f55d9eb8294', '2026-02-07 16:41:51', NULL, NULL, NULL, '2026-01-08 11:11:51'),
(255, 27, '14f10bf8cb9e5c4388287e46b1eb793dd5a8bf1023bdff4cf693d5ba8bf1b774', '2026-02-07 16:41:56', NULL, NULL, NULL, '2026-01-08 11:11:56'),
(256, 27, '2815f9802d94325000d5699f7567d24b28231a17123b3f3af2b14c4734ba4d86', '2026-02-07 16:41:59', NULL, NULL, NULL, '2026-01-08 11:11:59'),
(257, 27, 'eb8030672246d2780599fda1b96d0433a96b62c9d3c6a6fb3828398b8130ad52', '2026-02-07 16:42:05', NULL, NULL, NULL, '2026-01-08 11:12:05'),
(258, 27, '1aa125a9a18557fe1f9baee96a8cd2cfb97b961a7ff98a920e725648cc7b00f7', '2026-02-07 16:42:06', NULL, NULL, NULL, '2026-01-08 11:12:06'),
(259, 27, 'caa309cc230e40a402037f897602dfd082f3758c9a086f03ed664804f11d1688', '2026-02-07 16:42:08', NULL, NULL, NULL, '2026-01-08 11:12:08'),
(260, 27, 'ccb9c81379df1fc413324338c569b3caabdff53bc321207b45cf0c4413eadc58', '2026-02-07 16:42:11', NULL, NULL, NULL, '2026-01-08 11:12:11'),
(261, 27, '369a469ecc033fac98ce86a2d67d53f7b1eac1820e52d051c5a0da2fe95d0f30', '2026-02-07 16:42:11', NULL, NULL, NULL, '2026-01-08 11:12:11'),
(262, 27, 'e2169f557fa87c7765d6bfe7d4476ee071b0b9f69620f8658f40b7b0b41a4edd', '2026-02-07 16:42:11', NULL, NULL, NULL, '2026-01-08 11:12:11'),
(263, 27, '674ea9124e3dc5c910892b06105af7983920b4a9abe75cf9a920b6e9b784d310', '2026-02-07 16:42:19', NULL, NULL, NULL, '2026-01-08 11:12:19'),
(264, 27, 'a07d0dc6bd601b32e9e38afabe13cc6ac2afa6a1d08ca341f27c09198c10bb86', '2026-02-07 16:42:20', NULL, NULL, NULL, '2026-01-08 11:12:20'),
(265, 27, '63876d5c731c508e9c02aa37d02f19a98325618fdf1c7a10d61094fca7413165', '2026-02-07 16:42:24', NULL, NULL, NULL, '2026-01-08 11:12:24'),
(266, 27, '0f35d5fea267f42fde6c3e2b3dbd9f3114875f0f5674eedf0b9007c93a64bb56', '2026-02-07 16:42:27', NULL, NULL, NULL, '2026-01-08 11:12:27'),
(267, 27, '749430a3936c0a65c2245153460d2ccd23545aa64740ab86141cd8a11b51daac', '2026-02-07 16:42:27', NULL, NULL, NULL, '2026-01-08 11:12:27'),
(268, 27, 'ff286cf5b73fdb142fd27b440d431c6f30188592faef300e4afc96ce38dc38eb', '2026-02-07 16:42:29', NULL, NULL, NULL, '2026-01-08 11:12:29'),
(269, 27, '201ecf0f009e6bb5251cce18ed61cb136e98a91efca2453d4bea5e2f42933406', '2026-02-07 16:42:34', NULL, NULL, NULL, '2026-01-08 11:12:34'),
(270, 27, '86be455a0e5746fa76520f424e3651a560b7c33c1828a40548d013873ca96efd', '2026-02-07 16:42:39', NULL, NULL, NULL, '2026-01-08 11:12:39'),
(271, 27, '5152756b728a42d593c6520df69f61c10fd63cbb59e65cf4d677617500d269b2', '2026-02-07 16:42:41', NULL, NULL, NULL, '2026-01-08 11:12:41'),
(272, 27, '5d8b95805b2ea363743f69175f7fa611a394701184fbbc035d9b06aa1cdada33', '2026-02-07 16:42:42', NULL, NULL, NULL, '2026-01-08 11:12:42'),
(273, 27, '1316481d5d7710d6cce180665d7dd5f8ce1c492262b923c9353e020e08de5025', '2026-02-07 16:42:44', NULL, NULL, NULL, '2026-01-08 11:12:44'),
(274, 27, '19a13460483deb212d7ba5239ba3b2587accf8e6424b51ee3825974aaa374ea3', '2026-02-07 16:42:47', NULL, NULL, NULL, '2026-01-08 11:12:47'),
(275, 27, 'e22051744938336f92a805c3bf736fd4c070e74aae4438769485c80303d6e4dc', '2026-02-07 16:42:48', NULL, NULL, NULL, '2026-01-08 11:12:48'),
(276, 27, '91e12d8b8caea8d9dfb7dd5bc0b4b5c54db32d3516bf8c081f9670a46d3b3992', '2026-02-07 16:42:56', NULL, NULL, NULL, '2026-01-08 11:12:56'),
(277, 27, '73b16e198a5df10b738571ee1876abb82245fa6426424fcb06af631394c14b60', '2026-02-07 16:42:57', NULL, NULL, NULL, '2026-01-08 11:12:57'),
(278, 27, '0793a7393389516a9e548787a23e8e4e788853380ac9d773475261fa5337edb9', '2026-02-07 16:42:57', NULL, NULL, NULL, '2026-01-08 11:12:57'),
(279, 27, '6e030e6987d3efc59d7887638e29bfc3e2d5067312a69753bf9ec774c3f6599a', '2026-02-07 16:43:03', NULL, NULL, NULL, '2026-01-08 11:13:03'),
(280, 27, '4c6dace6e407867c433e516d2e1ff75ddb500204a131aa753118b63034429443', '2026-02-07 16:43:03', NULL, NULL, NULL, '2026-01-08 11:13:03'),
(281, 27, '1eb2e50ab3404ed8b822f6cc7a3f8b020d2fd77832025f8c8f083701fdd02ebb', '2026-02-07 16:43:11', NULL, NULL, NULL, '2026-01-08 11:13:11'),
(282, 27, '32a59c55281aa4c02983382c8e396f69ac1c15147e2da61089f62e985759b387', '2026-02-07 16:43:11', NULL, NULL, NULL, '2026-01-08 11:13:11'),
(283, 27, '8ffdd10d7ce406382825938aac3db3c06c787be8f8527c930ab14243d66b4740', '2026-02-07 16:43:12', NULL, NULL, NULL, '2026-01-08 11:13:12'),
(284, 27, 'a15273d4d3521b93eba42b7db13b70fecec5f0aa470f3ca9f159440678a76a06', '2026-02-07 16:43:19', NULL, NULL, NULL, '2026-01-08 11:13:19'),
(285, 27, 'dba89fd74ddf0e5071606b9e63e8d5c8358b1b99d8a4f9496055b79414fc61c1', '2026-02-07 16:43:19', NULL, NULL, NULL, '2026-01-08 11:13:19'),
(286, 209, '414d180d46bf6d731df4f2050229041e5d8b7ee88c6afcec153b518142d520eb', '2026-02-08 13:30:47', NULL, NULL, NULL, '2026-01-09 08:00:47'),
(287, 215, '38517369c5825af3e313dbdbf23ac4b96eb7377b3953a7af38380fca730bc38d', '2026-02-08 20:58:15', NULL, NULL, NULL, '2026-01-09 15:28:15'),
(288, 217, '2ab5c3db8b9b7c16d9ee6aeca38b7cb36372e6ac3e6cbacb4f98aace565fcdf9', '2026-02-09 00:30:06', NULL, NULL, NULL, '2026-01-09 19:00:06'),
(289, 219, '8af41e1fad97a4bf15f6061fa00d45780c701e59afae4e3d13c84261b2448eee', '2026-02-10 12:14:02', NULL, NULL, NULL, '2026-01-11 06:44:02'),
(290, 226, 'fa7c0a6153fb4131df5e3528bb1492112be34153cff066283e1c326110e0161b', '2026-02-11 23:21:56', NULL, NULL, NULL, '2026-01-12 17:51:56'),
(291, 228, '8fd8348ff6b11b71ab8780222a43f33fd419d2a27c9a659165f53bd9ce252d02', '2026-02-13 09:21:32', NULL, NULL, NULL, '2026-01-14 03:51:32'),
(292, 230, 'e41a476778c858f2e172c91132630fb9afca5e6a8fe588d5eb09bab9ed206006', '2026-02-15 12:27:45', NULL, NULL, NULL, '2026-01-16 06:57:45'),
(293, 233, '353e67d713a075b2c7832fcf59afc3af258d9bad1607c62d709966c4cf37600f', '2026-02-15 18:15:54', NULL, NULL, NULL, '2026-01-16 12:45:54'),
(294, 230, '234d73f8c5157044f4d16ca4ca2067d9655ea0e556f946b843c8bb7eb7df2b1b', '2026-02-19 15:35:27', NULL, NULL, NULL, '2026-01-20 10:05:27'),
(295, 239, 'c0034bd734a1a7a3ed906356edc63f4a16915b25149fa92d5a1cc314b6ac522b', '2026-02-20 18:31:15', NULL, NULL, NULL, '2026-01-21 13:01:15'),
(296, 240, '67348acf8b2af93052708cb236bd51f23dfd559ad1797d0cd2a12daed2e1e7b3', '2026-02-20 19:22:44', NULL, NULL, NULL, '2026-01-21 13:52:44'),
(297, 241, '9059020716c1662bdbada311f5e4211509e1f7e7f3c6d97f3a7859833279c2f6', '2026-02-20 20:24:05', NULL, NULL, NULL, '2026-01-21 14:54:05'),
(298, 243, 'e43463158088b6407f0fadcbc029c6e5d80652e9416cb961286bb2eafe19c7a5', '2026-02-22 13:45:08', NULL, NULL, NULL, '2026-01-23 08:15:08'),
(299, 245, '15409c7638b28dcf051974adda1005ae0a1cfdf11dc2fdec993f132dd78e5e80', '2026-02-22 14:28:10', NULL, NULL, NULL, '2026-01-23 08:58:10'),
(300, 230, '7400a201e4c5ed704bc6fa684d12e964e10b0cf36b211798f40f9720d2de0db1', '2026-02-22 15:32:30', NULL, NULL, NULL, '2026-01-23 10:02:30'),
(301, 247, '0253412a90deb877d9aa6017a8eabb8eca9eec7212e8e90179051eac4fab6b4b', '2026-02-22 19:00:46', NULL, NULL, NULL, '2026-01-23 13:30:46'),
(302, 250, 'ad1cc9562f82186faa99cd34cd55d56c640d2a83b3cc1a119b67ddc8d8690b01', '2026-02-22 22:29:32', NULL, NULL, NULL, '2026-01-23 16:59:32'),
(303, 241, '8db5c66cf4d0b8d50301be5b3f73abcf8e151958597231553cd22c3228af4c0a', '2026-02-22 23:52:41', NULL, NULL, NULL, '2026-01-23 18:22:41'),
(304, 241, '70206f575d07cb0f273ed5b224112cebf96bf873b33466989b64a51cf85542ba', '2026-02-23 00:05:47', NULL, NULL, NULL, '2026-01-23 18:35:47'),
(305, 252, '6c6873ef06701fc804f271706ec85ccaadf568297bf754b0c4e1f598dc287524', '2026-02-23 10:58:14', NULL, NULL, NULL, '2026-01-24 05:28:14'),
(306, 255, '4eee095f2a70916e81bae7b2cd36f54b71e1c39580ad10cf7e7ee174962987a6', '2026-02-23 14:50:44', NULL, NULL, NULL, '2026-01-24 09:20:44'),
(307, 109, '4fcc0cbd959974a00b4ba6c5688be600c29e1d29dbef616031c1dd7b3a86c3b4', '2026-02-23 16:14:29', NULL, NULL, NULL, '2026-01-24 10:44:29'),
(308, 133, 'd9e806157e5135838366d7ccbc10a495d540253b65bcf89c572d6d0809116be4', '2026-02-24 12:30:31', NULL, NULL, NULL, '2026-01-25 07:00:31'),
(309, 256, '4511f4ebe6646963bff369b3982d157b1fb9d16c4020f8abcdf593d92b80db57', '2026-02-24 23:37:51', NULL, NULL, NULL, '2026-01-25 18:07:51'),
(310, 259, '594c802d2e4163e7ff87a5380c622954980e1de872d71203a0bd8c36231771b5', '2026-02-25 20:28:46', NULL, NULL, NULL, '2026-01-26 14:58:46'),
(311, 241, 'bdb6c411ec40367b223cfe7b3b1f82789405558e6e8d0f1b21b1a20292651d07', '2026-03-01 10:29:01', NULL, NULL, NULL, '2026-01-30 04:59:01'),
(312, 241, 'ec140c2bbb2421f5f0616cd2f4f9068b0e2763d16905ce077cd85890061ddf87', '2026-03-01 14:36:56', NULL, NULL, NULL, '2026-01-30 09:06:56'),
(313, 264, 'fbb69b08a1bad6b23909808c8c6c201143d4cc6a090910510eb94f9f3a80302b', '2026-03-01 16:01:12', NULL, NULL, NULL, '2026-01-30 10:31:12'),
(314, 265, '317db232848cf3823ee38b78aa9864a6e48bceb30ff8aff24e26809395b65f49', '2026-03-01 16:26:12', NULL, NULL, NULL, '2026-01-30 10:56:12'),
(315, 241, '75549d8ef4b3b88e2587b7551871282d031f78ab346fe244bfe70da370b9fd52', '2026-03-01 17:02:15', NULL, NULL, NULL, '2026-01-30 11:32:15'),
(316, 266, '494442fb45b343075e095a64298aee24edd842c241bdd245ba707b909de74020', '2026-03-01 18:11:47', NULL, NULL, NULL, '2026-01-30 12:41:47'),
(317, 269, 'eedeb2fd3c12f5df4f465eebc5f5d7e2cca4350085ba69ebc50ec7ed7e834188', '2026-03-02 21:08:18', NULL, NULL, NULL, '2026-01-31 15:38:18'),
(318, 109, 'a1d51ab368724dadea1d96b0fd7b346b4f8ca165d77f899d1bb1fc461f34a4f1', '2026-03-02 21:28:35', NULL, NULL, NULL, '2026-01-31 15:58:35'),
(319, 272, '5edd7165d3e0ae207d3f5822c284f3e4eaa3e5bb406cf3e99715b15033eb647f', '2026-03-05 09:21:22', NULL, NULL, NULL, '2026-02-03 03:51:22'),
(320, 274, 'cf3cbd4860b1a192b16d2e8cc93c2218a173b979a5c07f80dfa13dfe32d85a73', '2026-03-06 13:55:58', NULL, NULL, NULL, '2026-02-04 08:25:58'),
(321, 27, '1808edf85a40229afb78aab4ae1ce2a245158ad6987355c62756c59da4b2f809', '2026-03-08 13:14:31', NULL, NULL, NULL, '2026-02-06 07:44:31'),
(322, 205, '5398332276a45cafbc3ddc5a6b38d1222f8dddd70d82725c67c1217d53b37457', '2026-03-10 19:43:20', NULL, NULL, NULL, '2026-02-08 14:13:20'),
(323, 279, '9aa829aaccb94ec973fb0883f58424e7a7425fb289c4728369d0f623b7f88ddd', '2026-03-11 06:20:14', NULL, NULL, NULL, '2026-02-09 00:50:14'),
(324, 279, 'bbaac302975a26856e1cb15d28df632a2cfafdf96d0209c106b55d3f182bb235', '2026-03-12 02:46:36', NULL, NULL, NULL, '2026-02-09 21:16:36'),
(325, 284, 'f59037768d9e50d4ba0c605c790fe9c355fa0bd24e70eb54986d726c896f45a1', '2026-03-12 19:56:24', NULL, NULL, NULL, '2026-02-10 14:26:24'),
(326, 287, '052da0149811c29e6201ffb8bb885930e5e3d9a22f66c7aed3881fab16e1efbf', '2026-03-14 06:14:40', NULL, NULL, NULL, '2026-02-12 00:44:40'),
(327, 288, '3137a60cee410af10d3e72c61ee94e8dc0f26c6f4cafd4dcf272bbd27d12c40d', '2026-03-14 10:46:26', NULL, NULL, NULL, '2026-02-12 05:16:26'),
(328, 289, 'f64afb1d707933cfccbe9e1999a7c0192ec6d4f1b643e149c2e419d4bb892b14', '2026-03-14 18:28:47', NULL, NULL, NULL, '2026-02-12 12:58:47'),
(329, 290, '6b666a6382b3a021fa99b3f1da605ec9471ab8db905c14bd7c992b185ded1043', '2026-03-15 20:10:05', NULL, NULL, NULL, '2026-02-13 14:40:05'),
(330, 292, 'daeb6b5429353db87efa8f658a991f74267598e6157c4cfd49b3e8a603b3f73e', '2026-03-16 11:32:14', NULL, NULL, NULL, '2026-02-14 06:02:14'),
(331, 293, '3a003e78ab2821eac61cd9ceb4a16784233297e70ec14319638bb3f86d3ca0f0', '2026-03-19 07:03:32', NULL, NULL, NULL, '2026-02-17 01:33:32'),
(332, 295, '910d1eae756c42db0334b81fa0d4c809d7133d0e5496f772cb7c1cd488033c56', '2026-03-19 13:40:51', NULL, NULL, NULL, '2026-02-17 08:10:51'),
(333, 299, '90b23722c8b928ee58be3136f32cb5b4e42c69790c03eae78248c2076ab6de29', '2026-03-21 19:31:17', NULL, NULL, NULL, '2026-02-19 14:01:17');

-- --------------------------------------------------------

--
-- Table structure for table `secure_file_access_logs`
--

CREATE TABLE `secure_file_access_logs` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `file_path` varchar(500) NOT NULL,
  `purpose` enum('view','stream','download') NOT NULL,
  `ip_address` varchar(45) NOT NULL,
  `user_agent` text DEFAULT NULL,
  `access_time` datetime NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `secure_file_tokens`
--

CREATE TABLE `secure_file_tokens` (
  `id` int(11) NOT NULL,
  `token` varchar(64) NOT NULL,
  `file_path` varchar(500) NOT NULL,
  `user_id` int(11) NOT NULL,
  `purpose` enum('view','stream','download') NOT NULL DEFAULT 'view',
  `expires_at` datetime NOT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `used` tinyint(1) NOT NULL DEFAULT 0,
  `used_at` datetime DEFAULT NULL,
  `ip_address` varchar(45) NOT NULL,
  `user_agent` text DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `secure_preview_tokens`
--

CREATE TABLE `secure_preview_tokens` (
  `id` int(11) NOT NULL,
  `token_hash` varchar(64) NOT NULL,
  `user_id` int(11) NOT NULL,
  `file_id` int(11) NOT NULL,
  `session_id` varchar(64) NOT NULL,
  `ip_address` varchar(45) NOT NULL,
  `user_agent_hash` varchar(64) NOT NULL,
  `used` tinyint(1) DEFAULT 0,
  `used_at` timestamp NULL DEFAULT NULL,
  `used_ip` varchar(45) DEFAULT NULL,
  `expires_at` timestamp NOT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;

-- --------------------------------------------------------

--
-- Table structure for table `secure_tokens`
--

CREATE TABLE `secure_tokens` (
  `id` int(11) NOT NULL,
  `token` varchar(64) NOT NULL,
  `file_id` int(11) DEFAULT NULL,
  `user_id` int(11) DEFAULT NULL,
  `expires_at` timestamp NOT NULL,
  `used` tinyint(1) DEFAULT 0,
  `used_at` timestamp NULL DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Stand-in structure for view `security_dashboard`
-- (See below for the actual view)
--
CREATE TABLE `security_dashboard` (
`total_security_events` bigint(21)
,`critical_events` bigint(21)
,`high_events` bigint(21)
,`session_attacks` bigint(21)
,`token_attacks` bigint(21)
,`last_hour_events` bigint(21)
,`last_24h_events` bigint(21)
,`unique_ips` bigint(21)
,`affected_users` bigint(21)
);

-- --------------------------------------------------------

--
-- Table structure for table `security_events`
--

CREATE TABLE `security_events` (
  `id` int(11) NOT NULL,
  `event_type` varchar(50) NOT NULL,
  `user_id` int(11) DEFAULT 0,
  `ip_address` varchar(45) NOT NULL,
  `user_agent` text DEFAULT NULL,
  `details` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`details`)),
  `severity` enum('low','medium','high','critical') DEFAULT 'medium',
  `resolved` tinyint(1) DEFAULT 0,
  `created_at` timestamp NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;

--
-- Triggers `security_events`
--
DELIMITER $$
CREATE TRIGGER `cleanup_old_sessions` AFTER INSERT ON `security_events` FOR EACH ROW BEGIN
    -- Clean up rate limit entries older than 1 hour
    DELETE FROM rate_limits WHERE created_at < DATE_SUB(NOW(), INTERVAL 1 HOUR);

    -- Clean up expired preview tokens
    DELETE FROM secure_preview_tokens WHERE expires_at < NOW();

    -- Clean up old security events (older than 30 days)
    DELETE FROM security_events WHERE created_at < DATE_SUB(NOW(), INTERVAL 30 DAY);
END
$$
DELIMITER ;

-- --------------------------------------------------------

--
-- Table structure for table `session_security`
--

CREATE TABLE `session_security` (
  `id` int(11) NOT NULL,
  `session_id` varchar(64) NOT NULL,
  `user_id` int(11) NOT NULL,
  `ip_address` varchar(45) NOT NULL,
  `user_agent_hash` varchar(64) NOT NULL,
  `start_time` timestamp NULL DEFAULT current_timestamp(),
  `last_activity` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `is_secure` tinyint(1) DEFAULT 1,
  `security_flags` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`security_flags`)),
  `ended_at` timestamp NULL DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;

-- --------------------------------------------------------

--
-- Table structure for table `site_settings`
--

CREATE TABLE `site_settings` (
  `id` int(11) NOT NULL,
  `setting_key` varchar(100) NOT NULL,
  `setting_value` text DEFAULT NULL,
  `setting_type` varchar(50) DEFAULT 'text',
  `category` varchar(50) DEFAULT 'general',
  `description` text DEFAULT NULL,
  `is_public` tinyint(1) DEFAULT 0,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `site_settings`
--

INSERT INTO `site_settings` (`id`, `setting_key`, `setting_value`, `setting_type`, `category`, `description`, `is_public`, `created_at`, `updated_at`) VALUES
(1, 'site_name', 'CyberWarLab', 'text', 'general', 'Website name', 1, '2025-07-18 02:05:05', '2025-07-18 02:05:05'),
(2, 'site_tagline', 'Elite Cyber Operations & Training', 'text', 'general', 'Website tagline', 1, '2025-07-18 02:05:05', '2025-07-18 02:05:05'),
(3, 'site_description', 'Advanced cybersecurity training and certification platform', 'textarea', 'general', 'Website description', 1, '2025-07-18 02:05:05', '2025-07-18 02:05:05'),
(4, 'site_email', 'admin@cyberwarlab.com', 'email', 'contact', 'Primary contact email', 1, '2025-07-18 02:05:05', '2025-07-18 02:05:05'),
(5, 'site_phone', '+1-555-CYBER-01', 'text', 'contact', 'Primary contact phone', 1, '2025-07-18 02:05:05', '2025-07-18 02:05:05'),
(6, 'site_address', 'Secure Location', 'text', 'contact', 'Business address', 1, '2025-07-18 02:05:05', '2025-07-18 02:05:05'),
(7, 'payment_gateway', 'stripe', 'select', 'payment', 'Primary payment gateway', 0, '2025-07-18 02:05:05', '2025-07-18 02:05:05'),
(8, 'currency', 'INR', 'text', 'payment', 'Default currency', 1, '2025-07-18 02:05:05', '2025-10-07 06:17:55'),
(9, 'tax_rate', '0.00', 'number', 'payment', 'Tax rate percentage', 0, '2025-07-18 02:05:05', '2025-07-18 02:05:05'),
(10, 'max_login_attempts', '5', 'number', 'security', 'Maximum login attempts before lockout', 0, '2025-07-18 02:05:05', '2025-07-18 02:05:05'),
(11, 'session_timeout', '3600', 'number', 'security', 'Session timeout in seconds', 0, '2025-07-18 02:05:05', '2025-07-18 02:05:05'),
(12, 'email_verification_required', '1', 'boolean', 'security', 'Require email verification for new users', 0, '2025-07-18 02:05:05', '2025-07-18 02:05:05'),
(13, 'maintenance_mode', '0', 'boolean', 'system', 'Enable maintenance mode', 0, '2025-07-18 02:05:05', '2025-07-18 02:05:05'),
(14, 'allow_registration', '1', 'boolean', 'system', 'Allow new user registration', 0, '2025-07-18 02:05:05', '2025-07-18 02:05:05'),
(15, 'exam_time_buffer', '5', 'number', 'exam', 'Extra time buffer for exams in minutes', 0, '2025-07-18 02:05:05', '2025-07-18 02:05:05'),
(16, 'certificate_validity_years', '2', 'number', 'exam', 'Certificate validity period in years', 0, '2025-07-18 02:05:05', '2025-07-18 02:05:05'),
(17, 'razorpay_key_id', 'rzp_live_RC0S7N7ThzQvV1', 'text', 'general', NULL, 0, '2025-09-16 04:11:04', '2025-09-16 04:11:04'),
(18, 'razorpay_enabled', '1', 'text', 'general', NULL, 0, '2025-09-16 04:11:04', '2025-09-16 04:11:04'),
(19, 'demo_mode_enabled', '0', 'text', 'general', NULL, 0, '2025-09-16 04:11:04', '2025-10-12 11:38:19'),
(20, 'usd_to_inr_rate', '83.0', 'text', 'general', NULL, 0, '2025-09-16 04:11:04', '2025-09-16 04:11:04'),
(23, 'payment_gateway_version', '2.0', 'text', 'general', NULL, 0, '2025-09-16 04:46:33', '2025-09-16 04:46:33'),
(24, 'razorpay_live_mode', '1', 'text', 'general', NULL, 0, '2025-09-16 04:46:33', '2025-09-16 04:46:33'),
(25, 'last_db_update', '2025-09-16 04:46:33', 'text', 'general', NULL, 0, '2025-09-16 04:46:33', '2025-09-16 04:46:33'),
(26, 'contact_email', '', 'text', 'general', NULL, 0, '2025-10-07 06:17:55', '2025-10-07 06:17:55'),
(27, 'support_email', '', 'text', 'general', NULL, 0, '2025-10-07 06:17:55', '2025-10-07 06:17:55'),
(28, 'default_exam_duration', '60', 'text', 'general', NULL, 0, '2025-10-07 06:17:55', '2025-10-07 06:17:55'),
(29, 'default_passing_score', '70', 'text', 'general', NULL, 0, '2025-10-07 06:17:55', '2025-10-07 06:17:55'),
(30, 'max_exam_attempts', '3', 'text', 'general', NULL, 0, '2025-10-07 06:17:55', '2025-10-07 06:17:55'),
(31, 'registration_enabled', '1', 'text', 'general', NULL, 0, '2025-10-07 06:17:55', '2025-10-07 06:17:55'),
(32, 'debug_mode', '0', 'text', 'general', NULL, 0, '2025-10-07 06:17:55', '2025-10-07 06:17:55');

-- --------------------------------------------------------

--
-- Table structure for table `suspicious_patterns`
--

CREATE TABLE `suspicious_patterns` (
  `id` int(11) NOT NULL,
  `pattern_type` varchar(50) NOT NULL,
  `ip_address` varchar(45) NOT NULL,
  `user_id` int(11) DEFAULT 0,
  `pattern_data` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL CHECK (json_valid(`pattern_data`)),
  `risk_score` decimal(5,2) DEFAULT 0.00,
  `active` tinyint(1) DEFAULT 1,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;

-- --------------------------------------------------------

--
-- Table structure for table `system_settings`
--

CREATE TABLE `system_settings` (
  `id` int(11) NOT NULL,
  `setting_key` varchar(100) NOT NULL,
  `setting_value` longtext DEFAULT NULL,
  `setting_type` enum('string','number','boolean','json','text') DEFAULT 'string',
  `category` varchar(50) DEFAULT 'general',
  `description` text DEFAULT NULL,
  `is_public` tinyint(1) DEFAULT 0,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `system_settings`
--

INSERT INTO `system_settings` (`id`, `setting_key`, `setting_value`, `setting_type`, `category`, `description`, `is_public`, `created_at`, `updated_at`) VALUES
(1, 'max_login_attempts', '3', 'string', 'security', NULL, 0, '2025-08-04 04:26:25', '2025-10-13 04:41:19'),
(2, 'lockout_duration', '900', 'string', 'security', NULL, 0, '2025-08-04 04:26:25', '2025-08-04 04:26:25'),
(3, 'session_timeout', '7200', 'string', 'security', NULL, 0, '2025-08-04 04:26:25', '2025-08-04 04:26:25'),
(4, 'password_min_length', '8', 'string', 'security', NULL, 0, '2025-08-04 04:26:25', '2025-08-04 04:26:25'),
(5, 'email_verification_required', '1', 'string', 'security', NULL, 0, '2025-08-04 04:26:25', '2025-08-04 04:26:25');

-- --------------------------------------------------------

--
-- Table structure for table `target_ips`
--

CREATE TABLE `target_ips` (
  `id` int(11) NOT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `description` text DEFAULT NULL,
  `services` text DEFAULT NULL,
  `difficulty` enum('easy','medium','hard') DEFAULT 'medium',
  `status` enum('active','inactive') DEFAULT 'active',
  `created_at` timestamp NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `target_ips`
--

INSERT INTO `target_ips` (`id`, `ip_address`, `description`, `services`, `difficulty`, `status`, `created_at`) VALUES
(1, '192.168.1.100', 'Vulnerable web server with SQL injection points', 'HTTP, SSH, FTP', 'medium', 'active', '2025-08-05 04:52:58'),
(2, '10.0.0.50', 'Network server with weak authentication', 'SMB, RDP, SSH', 'hard', 'active', '2025-08-05 04:52:58');

-- --------------------------------------------------------

--
-- Table structure for table `time_based_access`
--

CREATE TABLE `time_based_access` (
  `id` int(11) NOT NULL,
  `access_token` varchar(255) NOT NULL,
  `file_id` int(11) NOT NULL,
  `expires_at` bigint(20) NOT NULL,
  `created_at` bigint(20) NOT NULL,
  `is_active` tinyint(1) DEFAULT 1
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `time_based_tokens`
--

CREATE TABLE `time_based_tokens` (
  `id` int(11) NOT NULL,
  `token_id` varchar(64) NOT NULL,
  `user_id` int(11) NOT NULL,
  `resource_type` varchar(50) NOT NULL,
  `resource_id` int(11) NOT NULL,
  `action_type` varchar(50) NOT NULL,
  `token_data` text NOT NULL,
  `signature` varchar(64) NOT NULL,
  `issued_at` timestamp NULL DEFAULT current_timestamp(),
  `expires_at` timestamp NOT NULL,
  `status` enum('active','used','expired','revoked') DEFAULT 'active',
  `ip_address` varchar(45) DEFAULT NULL,
  `user_agent` text DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `upload_analytics`
--

CREATE TABLE `upload_analytics` (
  `id` int(11) NOT NULL,
  `session_key` varchar(255) NOT NULL,
  `file_name` varchar(500) NOT NULL,
  `file_type` varchar(50) NOT NULL,
  `file_size` bigint(20) NOT NULL,
  `upload_method` enum('direct','chunked','streaming') NOT NULL,
  `folder_id` int(11) NOT NULL DEFAULT 1,
  `user_id` int(11) NOT NULL DEFAULT 1,
  `start_time` timestamp NULL DEFAULT current_timestamp(),
  `end_time` timestamp NULL DEFAULT NULL,
  `duration_seconds` int(11) DEFAULT NULL,
  `average_speed` decimal(10,2) DEFAULT NULL,
  `chunks_total` int(11) DEFAULT NULL,
  `chunks_completed` int(11) DEFAULT NULL,
  `retries_count` int(11) DEFAULT 0,
  `status` enum('completed','failed','cancelled') NOT NULL,
  `error_message` text DEFAULT NULL,
  `user_agent` varchar(500) DEFAULT NULL,
  `ip_address` varchar(45) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `username` varchar(50) NOT NULL,
  `email` varchar(100) NOT NULL,
  `password` varchar(255) NOT NULL,
  `full_name` varchar(100) NOT NULL,
  `phone` varchar(20) DEFAULT NULL,
  `profile_image` varchar(255) DEFAULT NULL,
  `user_type` enum('user','admin') DEFAULT 'user',
  `email_verified` tinyint(1) DEFAULT 0,
  `verification_token` varchar(100) DEFAULT NULL,
  `reset_token` varchar(100) DEFAULT NULL,
  `reset_expires` datetime DEFAULT NULL,
  `remember_token` varchar(100) DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `status` enum('active','inactive','suspended') DEFAULT 'active',
  `last_login` timestamp NULL DEFAULT NULL,
  `login_attempts` int(11) DEFAULT 0,
  `locked_until` timestamp NULL DEFAULT NULL,
  `email_verified_at` datetime DEFAULT NULL,
  `is_active` tinyint(1) DEFAULT 1,
  `failed_attempts` int(11) DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`id`, `username`, `email`, `password`, `full_name`, `phone`, `profile_image`, `user_type`, `email_verified`, `verification_token`, `reset_token`, `reset_expires`, `remember_token`, `created_at`, `updated_at`, `status`, `last_login`, `login_attempts`, `locked_until`, `email_verified_at`, `is_active`, `failed_attempts`) VALUES
(1, 'admin', 'admin@cyberwarlab.com', '$2y$12$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'System Administrator', NULL, NULL, 'admin', 1, NULL, NULL, NULL, NULL, '2025-07-18 02:05:05', '2025-12-31 08:32:10', 'active', '2025-09-10 10:22:24', 1, '2025-12-31 14:17:10', NULL, 1, 5),
(2, 'testuser', 'test@cyberwarlab.com', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'Test User', NULL, NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-07-18 02:05:05', '2025-07-22 10:40:37', 'active', NULL, 3, NULL, NULL, 1, 0),
(13, 'admin1', 'amitkumarnalwa9@gmail.com', '$2y$10$J2d0UyMXIfBObAFq3PLRoOn6.1hW/h.Np54Ez8KWxe5v/XWiRmsU6', 'Amit kumar Nalwa', '8059617232', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-07-25 01:07:03', '2025-11-11 04:40:08', 'active', '2025-09-25 05:06:40', 2, NULL, NULL, 1, 0),
(14, 'testuser_1753408111', 'test@cyberwarlab.in', '$2y$10$1PWBab.2SRA4efsZlpO5gOW86J0Gj6QimNsciwnu2NgqhaGlu5Q.2', 'Test User', NULL, NULL, 'user', 1, NULL, 'd82e13dcaf2f0f2dbdf97b2028dc9d078df0984dba57bb3324c4261f3ee8c488', '2025-07-25 08:18:33', NULL, '2025-07-25 01:48:31', '2025-07-25 01:48:33', 'active', NULL, 0, NULL, NULL, 1, 0),
(15, 'cyberwarlab_admin', 'cyberwarlab1@gmail.com', '$2y$10$u.KUalaA.tOkwZ2qv7XnWumCZg9ZaQSg3O2J05B0nUQRtfVBjHW.y', 'CyberWarLab Administrator', NULL, NULL, 'admin', 1, NULL, NULL, NULL, NULL, '2025-08-03 03:04:09', '2026-02-27 16:14:50', 'active', '2025-08-05 10:33:20', 0, '2026-02-27 21:59:50', NULL, 1, 14),
(20, 'sourabh98', 'sourabhkeshkar98@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$UUtENzdNLlQxYjBaekkzOA$FqtWig8+sQ3rvJc+l7vpwjJyvkrteFb/TGXgcRdRR/0', 'Sourabh Keshkar', '9755245279', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-08-08 05:32:44', '2025-08-08 05:54:29', 'active', '2025-08-08 05:54:29', 0, NULL, NULL, 1, 0),
(21, 'vatan4712', 'vatansingh688@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$Q3MvR1p2M0l2US9ValVvWA$uwbhT4KpR/j9BZ9ewG1LTgiRMTns74IgOqRmtGWp+p8', 'vatan Singh', '8451990648', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-08-08 06:47:28', '2026-02-02 12:55:10', 'active', '2026-02-02 12:55:10', 0, NULL, NULL, 1, 0),
(22, 'larass0x04', 'larass0x0d@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$Ylk5RmowdzRNQ3hFbHZQYg$fvBm9QYMNyQGlWNfZnGi8K5roflcp//GD2P7LFdcneg', 'larass0x04', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-08-15 09:39:56', '2025-08-15 09:58:03', 'active', '2025-08-15 09:58:03', 0, NULL, NULL, 1, 0),
(23, 'govindvaja', 'Vajagovind109@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$MVJZallBeTJqZzk5bkdRZg$lVpemnGcDF1ts9xMKTIEf8WfjYLoMhFQdExASsGZZ54', 'Govindbhai Rameshbhai vaja', '9904744672', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-08-15 10:50:44', '2025-08-15 11:05:05', 'active', '2025-08-15 11:05:05', 0, NULL, NULL, 1, 0),
(25, 'swefewwf', 'lbyztkjbkevagteglq@nesopf.com', '$argon2id$v=19$m=65536,t=4,p=3$a1gyV2o2NWhNenVIN2d5ag$iCE+rwnly0ELbXkr1qKv2hUmoFGocuVKnHhKUqSug6E', 'fdgfgfdgfd', '2266341234', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-08-27 02:33:49', '2025-08-27 02:35:04', 'active', '2025-08-27 02:35:04', 0, NULL, NULL, 1, 0),
(26, 'deadshot', 'deadshot9987@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$bUFIWnhPWUExZnBBTVRqSA$uMAZcnxyzeWEUd+KQwDFLbu5IN6lV8i2SQ6AvjnQq/s', 'Akshay Trimukhe', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-08-31 10:27:22', '2025-08-31 10:29:19', 'active', '2025-08-31 10:29:19', 0, NULL, NULL, 1, 0),
(27, 'mobilecyber', 'mobilecyber5050@gmail.com', '$2y$10$0FfZPSQTdbQaXzCcQ/L6t.Keh7qLK3PFtPCNri0hn469FFyUa6Gqm', 'Amit kumar', '8059717232', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-09-12 14:16:16', '2026-03-02 06:34:47', 'active', '2026-03-02 06:34:47', 0, NULL, NULL, 1, 0),
(28, 'vatan2103', 'vatansingh455@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$eUxOVVVxVDZvbWdjMngvZg$g5MgZrDvxEyz8kXwIizwd0/T7ivTcDnqtE0Hs9VCeFI', 'vatan Birendra Singh', '7304823392', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-09-19 04:05:33', '2025-11-23 08:15:32', 'active', '2025-11-23 08:15:32', 0, NULL, NULL, 1, 0),
(29, 'koppineedi', 'vamsilakshmisatyakoppineedi@gmail.com', '$2y$10$6orYpCjj93UzSmSB8JysYu5HvV4JQpmNdlFAq2eQ6m2nFTFfMiikW', 'Vamsi Lakshmi Satya Kumari Koppineedi', '9347596398', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-10-01 07:28:50', '2026-01-23 09:30:01', 'active', '2025-10-01 07:30:29', 0, NULL, NULL, 1, 0),
(30, 'KyawHan', 'kyawhansoe1999@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$c1FvOFVGVlNWanV4UlNYNQ$VYJX3h1C2+TGrvAh2aGGmcg0QQJcGPiY0Ev9vLICvzg', 'Kyaw Han Soe', '+959783300304', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-10-01 07:33:47', '2025-10-01 07:49:34', 'active', '2025-10-01 07:49:34', 0, NULL, NULL, 1, 0),
(33, 'Bongoni', 'goudd461@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$QjVxVXQvdHJFYkI4V0JkVw$VcpZcCJ/5slZHpdVkfHvMhcXIdBuJwV0FyscS65MB/c', 'Bongoni Devendar Goud', '7569208544', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-10-02 11:36:05', '2025-10-02 11:37:10', 'active', '2025-10-02 11:37:10', 0, NULL, NULL, 1, 0),
(34, 'mobilecyber1', 'networkingrouters1@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$YnJxbWozT3Q4dFpuL3VmQw$Y0hpBI1krL61AEo7SIImGTRvbaShwQiu+zuMfkYNMKI', 'Jagga', '8059617232', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-10-05 14:34:18', '2026-01-12 10:34:06', 'active', '2026-01-12 10:34:06', 0, NULL, NULL, 1, 0),
(35, 'Sonali', 'Sonalisalgar2017@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$Tzd3YldQclIzQWNoWDRMMA$uwQTUCFyJ65+Mgcu95crDUfM0CajQh65OGJBh7ihYr4', 'Sonali Chandrakant Salgar', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-10-13 05:05:02', '2025-10-13 05:06:48', 'active', '2025-10-13 05:06:48', 0, NULL, NULL, 1, 0),
(36, 'attacker', 'attacker@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$Y1lQdElTaTJNYTA2aHNTZw$MmVA7R+knISMn92hzsTCZdovfIR5H+BSqXY0yugCe3c', 'attaker', '', NULL, 'user', 1, NULL, '0b5fda02977bae8e0a9c21f9eb530e2ff0bb92310624a5af639d874a9bd6cc7a', '2025-10-26 13:33:16', NULL, '2025-10-25 06:11:46', '2025-11-01 10:31:36', 'active', '2025-11-01 10:31:36', 0, NULL, NULL, 1, 0),
(37, 'mgsouza343', 'mgsouza343@hotmail.com', '$argon2id$v=19$m=65536,t=4,p=3$TzdEdUU0TEMxN2NMVEptSA$j3dUi1LIH10KiVcAUJEG7KIdwJIvMjmHrOIc2+Nxc/E', 'MAURICIO GUIMARAES DE SOUZA', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-10-27 17:25:22', '2025-10-28 05:33:05', 'active', '2025-10-28 05:33:05', 0, NULL, NULL, 1, 0),
(38, 'Ibmuum', 'muumbi.mailu@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$R3pLWm5NN09nSTdnU2xkdw$pVdIoJgsL+woksB3WovMZr3CLCkZKZqlugnV1U6kW6o', 'Bonface Mailu', '0798295378', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-11-02 12:15:19', '2025-11-02 12:19:22', 'active', '2025-11-02 12:19:22', 0, NULL, NULL, 1, 0),
(40, 'prem', 'modipremkumar8274@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$WVgzLm1ZSkYuQXIxL3NtUQ$qP8ukWoHpZjEkLtwuCxO2d/kD3Q765kRheNxQaCqdvI', 'prem kumar', '8374534261', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-11-05 06:18:46', '2025-11-05 06:19:53', 'active', '2025-11-05 06:19:53', 0, NULL, NULL, 1, 0),
(41, 'Kalpesh264', 'dhamansekalpesh04@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$YVd1WUNSSmtQLk54cmpROQ$C70XEJH51r9Zd4P4BZITCq1nkxDgtsUXY4+rXlOvQUk', 'Kalpesh Dhamanse', '7875978950', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-11-13 05:37:52', '2025-11-13 05:43:17', 'active', '2025-11-13 05:43:17', 0, NULL, NULL, 1, 0),
(42, 'pushpak', 'pushpak.pandore@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$SkM4SGtOZlJoTzlaVzJqdg$RTNbreGuXpSHZEkNH+6CH54XwV+DrYB2g1XC/sgBRAc', 'PUSHPAK PANDORE', '+918767344736', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-11-13 17:51:08', '2025-11-13 17:52:50', 'active', '2025-11-13 17:52:50', 0, NULL, NULL, 1, 0),
(43, '001ilyess', 'ilyessellami04@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$NEh2c0pKWkI2c25tZG01Nw$BVOeL4ld0U4S3Vr/LOO8RDswGX1iEyRwwiBzmP6z6A8', 'Ilyess Sellami', '+21623831143', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-11-14 08:02:11', '2025-11-14 08:03:28', 'active', '2025-11-14 08:03:28', 0, NULL, NULL, 1, 0),
(44, 'jaleeth', 'jaleethlive@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$dW1XaWNIak41d0w2V2lMYQ$FUwJ0J8WGAdEnWn1jm6Zit6Eqxwz1Kk1jWudlTLSBZE', 'Aboo Jaleeth', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-11-15 10:56:50', '2025-11-15 10:57:56', 'active', '2025-11-15 10:57:56', 0, NULL, NULL, 1, 0),
(45, 'bigslim33', 'w.m.saunders00@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$Ym1ZQkFKSzUxaGpOdFJyQg$z4SvBovAzt3Sqnii+s6rEirk+mbApFnc79cVBfP5K9U', 'William Saunders', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-11-15 14:34:03', '2025-11-15 14:36:16', 'active', '2025-11-15 14:36:16', 0, NULL, NULL, 1, 0),
(46, 'azmelia', 'norazmelia89@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$TjBIbDMvaWxJZXZ0NnhwRg$VNXu+AqU43T2HkHUyU0j2nT3RtBv/cWN4OoEwEmnZ34', 'Nor Azmelia Azahari', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-11-16 14:14:00', '2025-12-16 09:15:44', 'active', '2025-12-16 09:15:44', 0, NULL, NULL, 1, 0),
(47, 'ravencodes', 'ravencodes0101@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$Yi5xSnFZTkNuNXJyZ3lnSQ$QUWboJa0rvO3Yn9UPxq0vXcgqBbyyHvY6LfHBPsaR24', 'Japheth Logsdon', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-11-19 21:44:07', '2025-11-19 21:44:54', 'active', '2025-11-19 21:44:54', 0, NULL, NULL, 1, 0),
(48, 'htunaungkyaw', 'drhtunaungkyaw1993@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$MW55ZVUzMk5jRkVPWkx5NA$1lTmFVHRdsM4HAchY7hQCh2yg35+0JZBCsJBCgkukwU', 'Htun Aung Kyaw', '+66646642724', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-11-20 17:26:33', '2025-11-28 03:52:09', 'active', '2025-11-28 03:52:09', 0, NULL, NULL, 1, 0),
(49, 'abrahams0x0', 'neuronebulax@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$L3I2a1Y1VzZ3cDVoTkNsYQ$oh18GD0NLSrxLH45gmkJunxJ7AaLL51uHRz7eoxkjBI', 'abram', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-11-21 06:42:18', '2026-01-27 07:24:05', 'active', '2026-01-27 07:24:05', 0, NULL, NULL, 1, 0),
(50, 'fibersecure', 'martinesegese47@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$ZHhFcXRjQ0M3VloxcEJZcA$Zym28/9oe5864wPv7IcjFv3Xdx/R0M7pdny6F9PzGLU', 'Martine Segese', '0768728784', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-11-23 08:52:15', '2025-11-23 09:26:13', 'active', '2025-11-23 09:26:13', 0, NULL, NULL, 1, 0),
(51, 'Harikrishna', 'dummymail77889@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$NWdwYkdFeXU2bGIyOHNaSg$3CnpK+Omf98pZ2xS+7ElGwS9BrL1lof4X2MOMYrqpOs', 'HariKrishan M', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-11-24 05:19:54', '2025-12-05 08:00:47', 'active', '2025-11-25 05:33:11', 0, NULL, NULL, 1, 3),
(52, 'nikhil4712', 'nikhilraut0021@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$MjBGMEszaWVjV3FsRElKMw$G1ZG+EbJv9ay/LtTU7ZCLQjgZCwTxvMcMVeVZt/+5ZA', 'Nikhil Raut', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-11-24 18:15:53', '2026-01-03 13:36:01', 'active', '2026-01-03 13:36:01', 0, NULL, NULL, 1, 0),
(53, 'VarunChugh', 'chugh.varunhm@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$VjNBMGFwUlZjNnRxb096OQ$hg8GNLveRd8Q/D7Ce5UiaCEDmnePQwFXul2j7CBCxC4', 'Varun Chugh', '+919896407700', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-11-25 08:43:33', '2025-11-25 08:47:03', 'active', '2025-11-25 08:47:03', 0, NULL, NULL, 1, 0),
(54, 'Rahul21', 'v4454595@gmail.com', '$2y$10$D6/MKn5MoL/FhdDfCsMbYe9oKzDol.3/iAtl7bF5TLC1C1q.THQUm', 'Rahul Gupta', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-11-25 10:54:21', '2025-11-26 05:03:31', 'active', '2025-11-26 05:03:31', 0, NULL, NULL, 1, 0),
(55, 'furious5', 'muneebnawaz3849@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$MWVhSHFXQzU3LzhnNy4zOQ$alfwjjp3WVRhd6gkOM3yYr63CxpllmKaeEFi3fFlMs4', 'Muhammad Munib Nawaz', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-11-25 15:05:29', '2025-11-25 15:07:52', 'active', '2025-11-25 15:07:52', 0, NULL, NULL, 1, 0),
(56, 'arinmandre', 'mandrearin@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$cXdLOWw0LzIuVWJpV0cyMg$FP5oYFR4D/Ex9AzElNE2G2Glu9VvVMITeUpMulkDcdY', 'Arin Mandre', '9920908818', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-11-25 18:15:43', '2025-12-04 06:02:49', 'active', '2025-12-04 06:02:49', 0, NULL, NULL, 1, 0),
(58, 'balamkrishna12', 'bala.m.krishna12@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$OFhqamoxZWVHWnF6Mk9sOA$mpQp+u0gGG50+RnJXTGuH8snlPXcrBZcKNvykaxkxd0', 'balamuralikrishna p', '+918971220960', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-11-26 10:40:55', '2025-11-26 12:03:46', 'active', '2025-11-26 12:03:46', 0, NULL, NULL, 1, 0),
(59, 'Bala91', 'balamuralikrishnap8@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$ZGQudXY1NDhGOVZ3SDNCaQ$HBAtw3yaFmYttwgm8gHQB3GCo3gdsB0MfeUc5KxGPw0', 'Bala Murali Krishna', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-11-26 12:14:10', '2025-11-26 15:18:57', 'active', '2025-11-26 15:18:57', 0, NULL, NULL, 1, 0),
(60, 'priyal07', 'heypriyalpayal@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$REtSRzNhbmxBeGhRLlN2cw$Z5+yaLbJnSwDCbAPP4aYegWUifp6BdMC2/x7V3iNfkM', 'Priyanka Kumari', '+919693199196', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-11-27 05:56:49', '2025-11-27 05:58:00', 'active', '2025-11-27 05:58:00', 0, NULL, NULL, 1, 0),
(61, 'kamel', 'imadmohamedimad19@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$dFp0cEhPSlI1MGV0akpyUQ$nAzujRQMiFIzGKrx/HHlKYYNxZR+t8KdmJLTl2sFwAk', 'mekchouche kamel', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-11-27 10:06:53', '2025-11-27 10:31:45', 'active', '2025-11-27 10:31:45', 0, NULL, NULL, 1, 0),
(62, 'Shivamk7761', 'shivamraj8825101384@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$TVlZY1VwV29pYjdpc3JHbw$rZ8d6zPLPEdWG+ICfMSQDCGvhv+X194q51pUqQBDdp4', 'SHIVAM KUMAR', '7761861674', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-11-27 18:47:03', '2025-11-27 18:49:20', 'active', '2025-11-27 18:49:20', 0, NULL, NULL, 1, 0),
(63, 'yash', 'ybajolia@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$WDdVNWIyRjVFTmxGWXAwSg$pdLGW3QqjnPRSkvTBdMlPyez4b4j2qQDOx+ko5xx9SU', 'Yash Prajapati', '9425339866', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-11-28 07:11:24', '2025-11-28 07:19:34', 'active', '2025-11-28 07:19:34', 0, NULL, NULL, 1, 0),
(64, 'gowthamrayee', 'gowthamrai2005@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$ZjR2U1poY2tvcEpPdDA2TQ$ZVl57ZgdreOcRdHIWpaAHQvQzn9pfcdI9Gup6AFnkyg', 'RAYEE GOWTHAM', '6281279210', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-11-28 15:29:43', '2025-11-28 15:35:37', 'active', '2025-11-28 15:35:37', 0, NULL, NULL, 1, 0),
(65, 'muralifank', 'muralifank@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$OUF3YkZaSTRsRGV2WE9yZw$ZgZvRZlTBFmpD1kG9J2kCqFoctFRUsB2sViABRGG/mk', 'Murali fank', '9655089089', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-11-29 13:46:03', '2025-12-10 10:14:21', 'active', '2025-12-10 10:14:21', 0, NULL, NULL, 1, 0),
(66, 'Farhan', 'fa83231212@gmail.com', '$2y$10$WaV/qbvxOq/KtW.cRxDrhOGjDl4tQBbSxZGsfKGLGxrfdsUOfvXsS', 'Farhan Ali', '03224040818', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-11-29 17:15:21', '2025-12-09 12:16:33', 'active', '2025-12-07 12:59:54', 0, NULL, NULL, 1, 1),
(67, 'ChiruMahesh', 'MAHESH520004@GMAIL.COM', '$argon2id$v=19$m=65536,t=4,p=3$eFBmUFlIVGtKa2lVTVdwaw$CxkdKfpwkw7X7kaFuLtgCReMfjDpU3jaS1WxmangJCY', 'Goli Chiranjeevi Mahesh', '9963019761', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-11-30 09:29:29', '2025-11-30 09:31:18', 'active', '2025-11-30 09:31:18', 0, NULL, NULL, 1, 0),
(68, 'Rizzz', 'riyathakare37@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$bFJYQkl1NjZkUTl0Y1B5Sg$AtkFY1BYAdtxvdmvQ4js6pMEp9BOMMEAYyNJLs8m2AQ', 'Riya Thakare', '+917796813747', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-11-30 09:44:45', '2025-11-30 09:48:32', 'active', '2025-11-30 09:48:32', 0, NULL, NULL, 1, 0),
(69, 'Divya', 'divya776088@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$TTJ6TGhtcU5QZ0FYUkFPbw$eLVDNeM6WGlCZ9oXV8pUcLVav9onQVGflm6zk5mNPa4', 'Divya R', '7760882634', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-11-30 10:19:21', '2025-12-10 08:35:23', 'active', '2025-12-10 08:35:23', 0, NULL, NULL, 1, 0),
(70, 'alv63', 'alireza.vahdati@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$ZHBUWGFWSGZ6LlRrQ1c1Vw$HL8QbQydSAQbQy81MmZCDoxaxRd0u/RnZaNL8b1MGNE', 'Alireza Vahdati', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-11-30 11:03:41', '2025-11-30 11:04:09', 'active', '2025-11-30 11:04:09', 0, NULL, NULL, 1, 0),
(71, 'Wallace', 'olawaleadeola19@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$dHl3d3hDbUxnTFpFdy5QRw$/ooBvoFJJScaC11OqgG1c0loxVVXPbnjQX+m8H/CDAw', 'Olawale Abdulahi', '+2348130558407', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-11-30 11:11:39', '2025-11-30 11:51:21', 'active', '2025-11-30 11:51:21', 0, NULL, NULL, 1, 0),
(72, 'mkpkmkpk', 'mkpkmkpk@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$ZWVJZGZjNjVqZktCR1c3Wg$lDCmepbjXzi9yFqB0Yv9yCTKwqDNSJivS7v1HGYWCS8', 'Marcin Krawczyk', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-11-30 11:18:47', '2025-11-30 19:45:39', 'active', '2025-11-30 19:45:39', 0, NULL, NULL, 1, 0),
(73, 'Jana', 'janagans99@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$V3BvMURGLzRhdHhhQ2w3WQ$Swj4ecR5/AcY1zOaZVL64DRQmZvGSMvgO1EqUPGpmZU', 'Janagan', '6379210886', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-11-30 11:54:22', '2026-01-24 02:20:34', 'active', '2026-01-24 02:20:34', 0, NULL, NULL, 1, 0),
(74, 'Georgekw', 'georgechennattkw@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$Rm5PRjFRNVZRTUowL3k0YQ$GIiDLhZRfqLu/7OH2w7f9Fzdx65kbX1bi9Ls4z7Rl3o', 'George Louis Joseph', '+96566712414', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-11-30 12:05:18', '2025-12-10 22:19:53', 'active', '2025-12-10 22:19:53', 0, NULL, NULL, 1, 0),
(75, 'pjayro', 'umonduonofit@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$VlZ4U3lnY250ZTBOV2Z4Rw$U1gGivDktwg27LUMbu9n/L6iKZGe70YH7bfutigAbHY', 'NDUONOFIT EFFIONG UMO', '+2348037955540', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-11-30 12:17:31', '2025-11-30 12:26:33', 'active', '2025-11-30 12:26:33', 0, NULL, NULL, 1, 0),
(76, 'rahuloffsec', 'rahulsmarttips@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$TGZpQ2NnRVlDcm1SaVhqWA$AEKUlctUxnRluBnPa3gytdoeTr1F/v32/F23YyTqwWc', 'Rahul Kumar', '7209568843', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-11-30 12:25:41', '2025-11-30 12:27:05', 'active', '2025-11-30 12:27:05', 0, NULL, NULL, 1, 0),
(77, 'zakariamaarak', 'maarak.zakaria03@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$UUw5RlFiTjFwTW9XTDRQLg$K2kc9lJJS9G5wtVf1ymTLf0OaKkN7WdVpIDKndTR0ak', 'Zakaria MAARAK', '+212708176267', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-11-30 12:54:05', '2025-11-30 12:54:28', 'active', '2025-11-30 12:54:28', 0, NULL, NULL, 1, 0),
(78, 'vasi22', 'vasi40568@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$alRHdHdDelRMSTBaaVczMA$jKvGzUaz20Qng1Kc7pDWOq3R3CZsrMxzUjPjFeHfgAg', 'Vasikaran', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-11-30 13:10:19', '2025-11-30 13:13:12', 'active', '2025-11-30 13:13:12', 0, NULL, NULL, 1, 0),
(79, 'Dubachandhu', 'dubachandhu2@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$dlk3MHhNN29QODFmMXZZSA$nIq+BxpHa0gJr2dv+VXBHEENSh8FRK23SGA22tk0d7o', 'Duba chandra sekhar raju', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-11-30 13:50:09', '2025-11-30 13:53:42', 'active', '2025-11-30 13:53:42', 0, NULL, NULL, 1, 0),
(80, 'Kalkidan_Belachew_Getnet', 'Kalkidanbelachewg@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$MVB0R3dLWHRTblVjbVE3RQ$nxH+Dc1LZ0hkHlj4ukiIpaWx8utr0qpQ9ftg/bFVIuM', 'Kalkidan Belachew Getnet', '+251900678055', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-11-30 14:37:03', '2025-11-30 14:38:07', 'active', '2025-11-30 14:38:07', 0, NULL, NULL, 1, 0),
(81, 'Vortex0710', 'aelmortaji7@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$alI1RUJGTVB1SnQ3cER0eg$guwwjX38rEpGWU3Q+xM1/oOUFvQbZD0BfgUE0MXDY8o', 'AYOUB ELMORTAJI', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-11-30 14:58:25', '2025-11-30 15:00:29', 'active', '2025-11-30 15:00:29', 0, NULL, NULL, 1, 0),
(83, 'pkbaria', 'prakash.baria@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$U3Y2cDFiWnJ3TGIzaDBNRA$X/TVXufvD9ULhL12txKIHfpimORtsBtLjZvaU2u7vIw', 'Prakash Kanji Baria', '9892124756', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-11-30 16:07:41', '2025-11-30 16:08:01', 'active', '2025-11-30 16:08:01', 0, NULL, NULL, 1, 0),
(84, 'AHMAD_ANAS_P_S', 'ahmadanas10504@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$cElRVDlNQi5Xb0xGYjh5dw$FAFvSJiBwMVbP2BFAMyS0hhpt/o1x/81+9eD3oDBSkM', 'AHMAD ANAS P S', '9489430023', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-11-30 17:07:38', '2025-12-11 18:27:45', 'active', '2025-12-11 18:27:45', 0, NULL, NULL, 1, 0),
(85, 'Mohamed_Elsayed_Emam_Abouelfotoh', 'mohamedelsied24@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$OUtyejB3QUt4bWtURHRINw$6LhVZHvoiQO5mRkscPT3G/l15hzOJx3/M3xn+5VWZKo', 'Mohamed Elsayed Emam Abouelfotoh', '+201157843935', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-11-30 17:15:56', '2025-11-30 17:17:58', 'active', '2025-11-30 17:17:58', 0, NULL, NULL, 1, 0),
(86, 'Saiteja_Reddy', 'basanisaitejareddy1213@gmail.com', '$2y$10$IXH6NuWemdeUrt2X/07Sq.wKuVGU80R2Z.sE5mGCruP3L68wJ7xsm', 'Saiteja reddy', '+918019478223', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-11-30 17:58:12', '2025-12-06 03:21:13', 'active', '2025-12-06 03:21:13', 0, NULL, NULL, 1, 0),
(87, 'Fares_Mohamed', 'fares.mohamed.hakim19@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$RW1EdnRwWnJ0bi82MWFkSg$zWpGdyzK2UJE1pTu3ZO8ZAlEdZ6kniByGsSNhcxyFRY', 'Fares Mohamed Abdelhakim Mohamed', '01065181901', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-11-30 17:59:51', '2025-11-30 18:00:10', 'active', '2025-11-30 18:00:10', 0, NULL, NULL, 1, 0),
(88, 'Karim_Nurudeen', 'karimnurudeen13@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$UVUwcnk1Qy96OUNjdGQxWA$D7b1Wd/aBbHyeP2YGaPb5/8DAnmITxPLeJ9sT5xL8xg', 'Karim Nurudeeen', '0598730049', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-11-30 18:07:07', '2025-11-30 18:30:59', 'active', '2025-11-30 18:30:59', 0, NULL, NULL, 1, 0),
(89, 'Vidhi', 'vidhi.2426mca191@kiet.edu', '$argon2id$v=19$m=65536,t=4,p=3$c09XWFJ3UXhQdEFuaGRGdw$BfAazcJgKW0HhFXFzMVrNcXcao9p3YJBgZRqmD7lJ8c', 'Vidhi Sharma', '6398609816', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-11-30 18:08:29', '2025-11-30 18:09:17', 'active', '2025-11-30 18:09:17', 0, NULL, NULL, 1, 0),
(90, 'dndr', 'oguzdundar1988@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$V2lRL3dKNm5nbkhlaHRCcg$YbcK9SIwdeORi9Oy+VqSBNIH1eQpLqGUJyD1vLAq0WQ', 'Oguz', '+905346344193', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-11-30 19:31:26', '2025-12-01 05:19:29', 'active', '2025-12-01 05:19:29', 0, NULL, NULL, 1, 0),
(91, 'King', 'kingsammy459@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$SGRpdWdkMjdXR2xOaEtKQQ$xBcIz43k/G/1kBv7wFNUeem5ns+oYD4raI8Wjooldgo', 'kingsammy459@gmail.com', '09157411633', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-11-30 20:43:43', '2025-11-30 20:50:58', 'active', '2025-11-30 20:50:58', 0, NULL, NULL, 1, 0),
(92, 'Pineroh', 'howardj.henriquez@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$ZjJ1TG9jNDVoMENiZlQ2Zg$fJkGU342b9leld6QjMMs0WKHZ7oNskD+FRTwhvMwARI', 'Howard Henriquez', 'pineroh', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-11-30 21:45:13', '2025-11-30 21:52:12', 'active', '2025-11-30 21:52:12', 0, NULL, NULL, 1, 0),
(93, 'mikun', 'dadaayomikun11@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$QmpITzlsMHNiclRYNkF5Sw$z2U6xvpFPjWsXiUFEazDbqdo1P77GxmnO2Y7RcQSQNo', 'Dada-Lucas Ayomikun', '+2348024009304', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-11-30 22:23:33', '2025-11-30 22:32:09', 'active', '2025-11-30 22:32:09', 0, NULL, NULL, 1, 0),
(94, 'imane', 'imaneelaffassi@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$STJnRjVLbUZLTUw3bFNGaQ$jK5E/TDomQGs1z1nwFO6nZK4PU5lgdx872SkGPDSIvo', 'imane el affassi', '0783509215', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-11-30 22:40:09', '2025-11-30 22:41:03', 'active', '2025-11-30 22:41:03', 0, NULL, NULL, 1, 0),
(95, 'elysian', 'aetheria.artemis@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$aTV5czZCTUE0cHVqcjNTRQ$VSC6Qmlw8oiPOtvj3IkipFr7wATjadusGhGyf/3zpzw', 'Anjali Panchal', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-11-30 23:07:15', '2025-11-30 23:08:08', 'active', '2025-11-30 23:08:08', 0, NULL, NULL, 1, 0),
(96, 'sarathi', 'mahasarathi465@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$ZWpIazYuQU1PM05DU0M3OA$oA933S0OK8v3C8yrzIGIYNHZundkPqINU/J3ufKoKw4', 'Mahasarathi p', '6382027641', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-01 00:06:09', '2025-12-02 08:13:15', 'active', '2025-12-02 08:13:15', 0, NULL, NULL, 1, 0),
(97, 'aaronamran', 'aaronamranba@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$Ym13dHNtUFF2cThyMDN1Nw$9qAUpdbGVXDJRnbnnwbiOa52CMRCqLDPcAdJgwJ+CcU', 'Aaron', '+60168846939', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-01 02:41:24', '2025-12-01 02:46:42', 'active', '2025-12-01 02:46:42', 0, NULL, NULL, 1, 0),
(98, 'Tamson', 'leaktal@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$NDBGcE11VkllS1cxV1RzcQ$JEIVUW0gWN9V4wAo8BwTlEPz6S4pojwVPMTSKVet4GA', 'Tamaine Aries Leak', '17573743918', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-01 02:49:58', '2025-12-09 20:07:32', 'active', '2025-12-09 20:07:32', 0, NULL, NULL, 1, 0),
(99, 'Shubha', 'shubhasep22@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$cWYzOC5zL1JwT2NKU0VpVQ$2g1c1X0ZtLmxWwHrcwNV9UD4AZmXNIns/vl7HLpmEds', 'Dr Shubha N', '+917892018234', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-01 03:26:47', '2025-12-01 03:27:37', 'active', '2025-12-01 03:27:37', 0, NULL, NULL, 1, 0),
(100, 'ahmed', 'muhammadahmed150290@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$UmJvL2pRLktmQ0Z5alNrNw$iuVD934yFD85Y1heNPKFRe520p3TPqqeU7xyBNNI168', 'Muhammad Ahmed', '+923210540003', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-01 04:35:05', '2025-12-01 04:37:42', 'active', '2025-12-01 04:37:42', 0, NULL, NULL, 1, 0),
(101, 'destenny99', 'kehindeakinsuroju99@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$S25qdG9SWGRaUi5XVUhaWQ$B4tdhIkMDzn60ihKSQVDUouF6COZPWudy+mopYk5uEE', 'Kehinde Akinsuroju', '4692125311', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-01 05:04:31', '2025-12-01 21:48:20', 'active', '2025-12-01 21:48:20', 0, NULL, NULL, 1, 0),
(102, 'nadine', 'nadineshua12@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$cFRKTUNTT1FFVU1UbE4uMg$rJoSa3C7nU9fYLm/LlsPMxPi76odnvN3/gk95PeOw10', 'Nadine', '081212047020', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-01 07:40:09', '2025-12-01 07:42:12', 'active', '2025-12-01 07:42:12', 0, NULL, NULL, 1, 0),
(103, 'rpurnama', 'blackhorse20032001@yahoo.com', '$argon2id$v=19$m=65536,t=4,p=3$M1p5R05xLnhCZ2dacGZ0MA$+8mbFOaEjsR++pMkBF2IfqGi/KYKWv5Kb7JuwLrZTDc', 'Rakhmadian Purnama', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-01 07:47:59', '2025-12-01 07:49:25', 'active', '2025-12-01 07:49:25', 0, NULL, NULL, 1, 0),
(104, 'nimesh', 'nalikajayarathna5@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$dFZxN3pWc08uVHM4SkRvUQ$DO3k5ZYQvHx+iRnFFKc1e8OspcFtzRbCOPToDDusDC0', 'Kumara Hannadige Nimesh Akalanka Peiris', '+94724364372', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-01 09:52:52', '2025-12-01 09:54:37', 'active', '2025-12-01 09:54:37', 0, NULL, NULL, 1, 0),
(105, 'sagar', 'sujithsagar75@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$TEpjSW5aemZVZVQ3MWdwTQ$VTsnX4TFlnIdgU1WAeQSptp+ZxAMD/9zKqObXRu1ZIc', 'Sagar Tedlapu', '+919640307874', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-01 11:13:46', '2025-12-01 11:13:56', 'active', '2025-12-01 11:13:56', 0, NULL, NULL, 1, 0),
(106, 'Matimba', 'timbze71@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$bnRyTTdlc0k2SnE4UkhkZA$JUPaU1vB8BxxeF3fMd5DnjeEIx0p6URWhB5zWpm06Sk', 'Matimba Maluleke', '+27606794975', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-01 11:37:49', '2025-12-01 11:42:45', 'active', '2025-12-01 11:42:45', 0, NULL, NULL, 1, 0),
(107, 'Blessing', 'blessingsemwayo7@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$Ny5XdnRsVC5Zd1lhWDNqOQ$PE08Veto6WPs41v/l3XsJ/DDHzraMys0DatTdUVZWmI', 'BLESSING SEMWAYO', '+27815969767', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-01 12:20:47', '2025-12-01 12:22:04', 'active', '2025-12-01 12:22:04', 0, NULL, NULL, 1, 0),
(108, 'Psychopomp', 'tolentino.ronaldb25@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$R0RyMU9VczB4S1AybDFheA$IDLI50990v3GrJAU+v+oivz+w8vSCSEHW13CBXbx9Qk', 'Ronald Tolentino', '+639157658787', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-01 13:42:37', '2025-12-01 13:44:17', 'active', '2025-12-01 13:44:17', 0, NULL, NULL, 1, 0),
(109, 'Sanika', 'pokharkar0809@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$M05TU1hWcDBhMFc1Zy9rLw$Ll3wSAO7i5o7URD93ENhmD3ZT1tZJ7JcOvi289lzFjQ', 'Sanika Pokharkar', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-01 16:03:01', '2026-01-31 15:58:35', 'active', '2026-01-31 15:58:35', 0, NULL, NULL, 1, 0),
(110, 'anon4712', 'anondevils2@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$dm9uRno3dWNQbGdpaGNtUw$5FXfb9bsONuuM3DbU5+IRXuMsBDv0kSzPCQmPzC3R2s', 'anon', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-01 16:20:40', '2026-01-21 11:57:22', 'active', '2026-01-21 11:57:22', 0, NULL, NULL, 1, 0),
(111, 'fahad_mahar58', 'fmahar346@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$Y1VnaVk3ZU90Zmg4RzcxQg$W6jcILqVkRp56Uv0LmuJPkA2vBxX13Fomf7bI45b9VI', 'M FAHED ARSHAD', '03032387958', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-01 16:26:25', '2025-12-01 17:56:32', 'active', '2025-12-01 17:56:32', 0, NULL, NULL, 1, 0),
(112, 'Salman', 'salmanbackupdata74@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$eHF4c1NwMW80V3NqYWpMVA$TW5eYoGO3CjpWzLWNGmJVFZUxUtvvpgIJD8tIwTD/gA', 'Mukhamad Salman', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-01 16:53:51', '2025-12-01 16:54:35', 'active', '2025-12-01 16:54:35', 0, NULL, NULL, 1, 0),
(113, 'hamet', 'hamet24@hotmail.com', '$argon2id$v=19$m=65536,t=4,p=3$UHlOMUdyT2M1TUtHNzN6Rw$oeMfa7H9wu3bFPL3Z9bnIgReDqlqIUU+UEfh4Ke7Xq4', 'YamidAmed Moreno', '3103898347', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-01 19:00:39', '2025-12-12 20:37:29', 'active', '2025-12-12 20:37:29', 0, NULL, NULL, 1, 0),
(114, 'ndchryso', 'ndchrysostome7@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$U0dEUWpZZ01saWVISmhOMg$e+Y94NTpzMOGMiSigJueeY7x/+moD2V9gU3fGFDMnlA', 'Jean Chrysostome NDAYISABYE', '+250789209482', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-01 19:12:21', '2025-12-01 19:15:18', 'active', '2025-12-01 19:15:18', 0, NULL, NULL, 1, 0),
(115, 'Sharon', 'sharonuzcategui@hotmail.com', '$argon2id$v=19$m=65536,t=4,p=3$VE82NXpoWlY2VVMuaGVjSw$mwPHS2p6hpkyHxh4NHhB9LKvPoq3OopUOHJ5Dl3O8+U', 'Sharon Iriana Uzcategui Perez', '+573243490133', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-01 19:50:50', '2025-12-01 19:51:05', 'active', '2025-12-01 19:51:05', 0, NULL, NULL, 1, 0),
(116, 'HRAP', 'haroldmalone@yahoo.com', '$argon2id$v=19$m=65536,t=4,p=3$S1pkbFVKbE1GMUVtYk00aw$KxwP/HkF3Ta4peoRASpE4n76zSZ06oiSERsGhxO/Zcs', 'Harold Malone', '16192014154', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-01 23:25:27', '2025-12-01 23:36:29', 'active', '2025-12-01 23:36:29', 0, NULL, NULL, 1, 0),
(117, 'Amarnadh', 'amarnadh416@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$eWlyQXBQLjNFeEZlZUgyRQ$vgeODXgDCbhfYCDlyt6QHFOh3dSJAiDxUtLZdFcv3Pc', 'Amarnadh Kotnala', '8297908304', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-02 04:00:44', '2025-12-02 04:07:41', 'active', '2025-12-02 04:07:41', 0, NULL, NULL, 1, 0),
(118, 'Goldvin', 'goldvinbksi@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$VG9vUWdwNUpkTHI5c2twaw$YxsTPhiDmR82XL/kOPsCdYLsYx4p90cGl8QM51QxsDM', 'Muhammad Goldvin Wijayakusuma', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-02 04:26:18', '2025-12-02 04:27:11', 'active', '2025-12-02 04:27:11', 0, NULL, NULL, 1, 0),
(119, 'Sriharish05', 'sriharishjayabalan@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$dm05SEIxUXYuNFlyL2JVdQ$S1cPXNgF1U93PIuCkychlVvTj8Aoo6IN5WlBBrllEHE', 'SRIHARISH V J', '+918668135837', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-02 05:32:34', '2025-12-02 05:35:05', 'active', '2025-12-02 05:35:05', 0, NULL, NULL, 1, 0),
(120, 'anon21', 'fixal42818@idwager.com', '$argon2id$v=19$m=65536,t=4,p=3$RW5lbnQuTENiTjVqQU9TeQ$h3eA4XsW+/JpCslc3Dm5Cxn6u8i4kYk4oRbNDv3ltIY', 'anon', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-02 07:07:20', '2025-12-02 07:07:20', 'active', NULL, 0, NULL, NULL, 1, 0),
(121, 'Armand', 'neuronasobreviviente@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$TG5UN1FkZnB5REVsQzNBUA$SzDjK32PDc1CnGH9Tvth/IEDBTYgw6s6aNvtcyJjo04', 'Armand', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-02 07:36:01', '2026-01-27 07:25:04', 'active', '2026-01-27 07:25:04', 0, NULL, NULL, 1, 0),
(122, 'Manjunath', 'manjunath2092005@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$RWRjdnRncU5XbU5tMktSSQ$446PtRv6k8qEr+xjUszHCSLrFoR5mr1JhjUq7tZT0iI', 'Manju Manjunath', '+919949918622', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-02 08:04:21', '2025-12-02 18:25:45', 'active', '2025-12-02 18:25:45', 0, NULL, NULL, 1, 0),
(123, 'gracecyber', 'gracevine2008@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$SW1vYzVHamk5QXdYYXh3Lw$EySakeRO1M2r/aW8mog7FejZd6HLrbmsVttwpoj1y0U', 'Ajayi Oluwaseyifunmi', '+2348035306973', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-02 08:43:20', '2025-12-02 08:47:39', 'active', '2025-12-02 08:47:39', 0, NULL, NULL, 1, 0),
(124, 'utun3n', 'kirimijoy77@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$aFZPU3IyM1Y0MnRNVXBUcg$FQqPRvrCAFCdCxO+NLyvvBilhipBGj9SxP/f/sM+AkM', 'Joy Muthoni Kirimi', '+254785539354', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-02 09:29:05', '2025-12-02 09:31:48', 'active', '2025-12-02 09:31:48', 0, NULL, NULL, 1, 0),
(125, 'qwerty', 'bhavan122005@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$SFBFa3VxS3pKMUxCT0Nwbg$87lZJ8LhNIlXs8WnGvVQ5XGiyyoi3kR3Ty+wgM4mFLw', 'Bhavan K', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-02 15:02:38', '2025-12-02 15:04:25', 'active', '2025-12-02 15:04:25', 0, NULL, NULL, 1, 0),
(126, '__jenika_', 'jenika1806@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$Y0hid1E2R0IzcnJGbmZRbA$/sDOwV7aTxPzNn8ZKtjpGg8PtWLg+VUxgATkSHzfNvI', 'Sahaya Jenika C', '9791876997', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-02 15:07:12', '2025-12-02 15:07:45', 'active', '2025-12-02 15:07:45', 0, NULL, NULL, 1, 0),
(127, 'Jagathlal', 'jagathlal.s4@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$UlRIZmJqdE0vZXVRVjdjNA$RWyDt1PgwA2Pym9n4RcEp6E0ICgul7TOgwurZu1KfUg', 'Jagathlal s', '7356322172', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-02 15:09:09', '2025-12-02 15:10:55', 'active', '2025-12-02 15:10:55', 0, NULL, NULL, 1, 0),
(128, 'idahosa10', 'idahosaea@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$S3l3M3lKcEcybWk3MGZ0dw$GJg9KE/O1vK+LkWrmeVdBKyOxcEwZ7ZXhvPeuu8g3ts', 'ehigie  idahosa', '15126602614', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-02 19:12:57', '2025-12-02 19:14:50', 'active', '2025-12-02 19:14:50', 0, NULL, NULL, 1, 0),
(129, 'braveheart', 'aman.learn25@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$SmJONmJ0dUR2RlFEc1hhSg$fz5TqQXYeJfX6zqOofQYuqN7KT2r+NA1A+2Ko5NIHDE', 'Amandeep Singh', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-02 20:03:52', '2026-02-27 14:58:57', 'active', '2026-02-27 14:58:57', 0, NULL, NULL, 1, 0),
(130, 'Ramona25', 'monaramona0@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$YU1CWlNBS3pvRkljSEg1OA$egff9FNgQkLEJaRpsNuglwq4nh7S+JSEGkkryeNZp1I', 'Ramona Rotila', '+13214510580', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-03 02:08:27', '2025-12-03 02:08:27', 'active', NULL, 0, NULL, NULL, 1, 0),
(131, 'tknisley', 'tstanley9300@stu.ftccollege.edu', '$argon2id$v=19$m=65536,t=4,p=3$eno5dFNqOUtjcjNFc2RIQQ$QG2CfZgg+ZN3prsazZxhJDRyc9fju30m7v6uPqAd5Oc', 'Tosha Knisley', '18632024296', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-03 03:39:28', '2025-12-03 03:43:52', 'active', '2025-12-03 03:43:52', 0, NULL, NULL, 1, 0),
(132, 'manahil_urooj20', 'manahilurooj20@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$aFQ2MUlrd3dYNGI3ZGRWYg$+wwRZTDAMPTxUFXbHFDPHqkogU0EtqjCzTB2bB4KZBo', 'Manahil Urooj', '03142787199', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-03 10:52:39', '2025-12-03 10:54:31', 'active', '2025-12-03 10:54:31', 0, NULL, NULL, 1, 0),
(133, 'DigiLog', 'lakshyatheinvincible123@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$MWZhRUQuYnNtaVFieEdrVA$y6lueQNvLMFttzpWuPn7W3JWi3wk8JkX2OcXlHDcKXc', 'Lakshya Sharma', '+916350068440', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-03 13:53:43', '2026-01-25 07:01:28', 'active', '2026-01-25 07:01:28', 0, NULL, NULL, 1, 0),
(134, 'Oluwatunmise', 'tunmisedaniel2009@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$L0pGTnovU0ZOcURlZXJmbQ$pCvAjLNpMfP8Vn/EUVCSWKg3q+tg2OLEM+F4acGAgS8', 'Akeju Oluwatunmise Daniel', '+2348149507414', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-03 17:22:08', '2025-12-03 17:28:30', 'active', '2025-12-03 17:28:30', 0, NULL, NULL, 1, 0),
(135, 'Didier', 'didierhounake@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$aWk3VTcvUGUxRE85NzZLZg$EfVJbYyekFT0PNdVbRSFkcy/bdzeXSC6dL/8tUgd6kk', 'Mawudjo Didier HOUNAKE', '+22899876887', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-03 20:35:16', '2025-12-03 20:43:16', 'active', '2025-12-03 20:43:16', 0, NULL, NULL, 1, 0),
(136, 'mudcal', 'mudenyo@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$TzFHa1dpdFA1NU02d25GRA$RcKllw1LkT36MRNAhw1bZGGGjphz0E8ikVSToF3/XAI', 'Caleb mudenyo', '+19095248803', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-04 04:20:52', '2025-12-04 04:23:28', 'active', '2025-12-04 04:23:28', 0, NULL, NULL, 1, 0),
(137, 'Dishant', 'Dishantsevak275@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$SkY1VktTSTBJOTVMdGdHWA$0PNDP8/5fK5VN62W/aEdC8TcLtpwnVdCjvAwyiUXOB0', 'Dishant sevak', '7023687240', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-04 06:04:31', '2025-12-04 06:08:57', 'active', '2025-12-04 06:08:57', 0, NULL, NULL, 1, 0),
(138, 'Samba12', 'sambayadav121@gmail.com', '$2y$10$5VHpj7sLc3/m6kcoBLx0Fe27uxFeNHeyDSvs.4oluoM91MdVbMnrm', 'Samba Siva Rao', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-04 06:55:44', '2026-01-28 18:26:04', 'active', '2026-01-24 06:54:31', 0, NULL, NULL, 1, 0),
(139, 'Rajesh', 'itsme.rajeshraj@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$T0JNemtqY3Vib2RadHEuaw$xH1/hRUVxpO1R2kHb/wK+0hDd+v+Nj+w3Pi7RmNZUWw', 'Rajesh Gurudu', '7799111990', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-04 18:58:46', '2025-12-21 11:50:16', 'active', '2025-12-21 11:50:16', 0, NULL, NULL, 1, 0),
(140, 'Rajin14', 'mohamedrajinprofessional@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$aVZXMVNvYUt4UlBpN2Eyaw$8/ofzNr1GFIZYv3ec6i3Icf8QVpsPgW+a051Q/ml77M', 'MOHAMED RAJIN', '9942419992', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-05 02:28:02', '2025-12-05 02:30:13', 'active', '2025-12-05 02:30:13', 0, NULL, NULL, 1, 0),
(141, 'bartek', 'janekoo@interia.pl', '$argon2id$v=19$m=65536,t=4,p=3$aWVKaFNKSm9SQkh2dmZGYg$YwOl7jEmFG+67q+2prWOYCtE8tAIBCyDUikS6Wr1YAE', 'Bartlomiej Wieczorek', '+48663201910', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-05 07:47:17', '2026-02-18 20:17:34', 'active', '2026-02-18 20:17:34', 0, NULL, NULL, 1, 0),
(142, 'HARI23', 'harishnarayanan843@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$dDRNekoyRC9yZnlKbS51dg$6wbDMjhC1ye1FUQr0BI28RvT0LSuusbfSviFAKSs1DU', 'HariKrishan', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-05 08:04:59', '2025-12-05 08:05:32', 'active', '2025-12-05 08:05:32', 0, NULL, NULL, 1, 0),
(143, 'adwithareddy', '24211a05w0@bvrit.ac.in', '$argon2id$v=19$m=65536,t=4,p=3$aU16VEJuY0VNemozTlY4ZQ$QxXj2vpVIlhlkFZar7mfsK91v3/l++/nemJbHuskSFw', 'Kudikala Adwitha Reddy', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-06 05:28:44', '2025-12-06 07:49:55', 'active', '2025-12-06 07:49:55', 0, NULL, NULL, 1, 0),
(144, 'korley', 'korleyd2727@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$YTFnd2g1WFZ5YXN5Zy9tUw$w8JN0acQLOrgrXI02Dx4bDngTwOQeP8A/anShXtbD4I', 'Korley obed Daitey', '+233543243591', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-06 10:27:27', '2025-12-06 10:44:31', 'active', '2025-12-06 10:44:31', 0, NULL, NULL, 1, 0),
(145, 'MuhammadAmmar', 'Ammaraamir777@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$dXJpSHRQcEUybVpFTjhKbw$M3QLNV1JFifVzw9yA3L2B76ZFJNd7rn8FCVH2WRpyRg', 'Muhamamd Ammar', '+923131888572', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-06 15:57:00', '2025-12-06 15:57:45', 'active', '2025-12-06 15:57:45', 0, NULL, NULL, 1, 0),
(146, 'Hermes68', 'gomez.H941@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$ejl1cENrWHZwVEl1aTh4aQ$9sJpehveWQPOVI7hJcjtpW3a1pnK9kyGEQWRVd0ASiY', 'Hermes Gomez', '17134293316', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-06 19:57:28', '2025-12-07 16:29:43', 'active', '2025-12-07 16:29:43', 0, NULL, NULL, 1, 0),
(147, 'vikkoya', 'vs833280@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$TFd0Z2JuZ05ra0dROEVIZQ$GSzOaS58mSkkqFwX35WxFDkerj9T9KFki5Xg8uf3KFA', 'Vikas k', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-07 13:26:19', '2025-12-07 13:31:12', 'active', '2025-12-07 13:31:12', 0, NULL, NULL, 1, 0),
(148, 'er_bhavesh', 'er.bhavesh13@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$VUtTQXRpNnI3R3o2SVQyNg$0uCJCsFwG3UmerYE6m1MBTPf7g/BLe2Vmjez0vOSVQE', 'er.bhavesh', '9662430077', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-07 15:04:16', '2025-12-07 15:05:04', 'active', '2025-12-07 15:05:04', 0, NULL, NULL, 1, 0),
(149, 'jerealbert', 'biderjeremias71@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$TzJiS2ZxUnVuYThkclM2TQ$aQzfoMm9chgDGh/8LulWZk2V6LXX8FCjVVeV0HSxY9c', 'Jeremias Alberto', '+244921839416', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-08 06:56:38', '2025-12-08 06:58:52', 'active', '2025-12-08 06:58:52', 0, NULL, NULL, 1, 0),
(150, 'jaswanth', 'jaswanthraj080100@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$WEZzZDRXNVllY2M0L3M3cQ$mDw4eTpVtWrD6Bz5vJBel3G1Dsxu9053DfhEq+zQ51o', 'Jaswanth', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-08 07:09:26', '2025-12-08 07:13:41', 'active', '2025-12-08 07:13:41', 0, NULL, NULL, 1, 0),
(151, 'Arjun_Jadhav', 'arjun.jadhav0024@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$c3dnckM5WDQua3RWQWVrRw$bmk6jOaQblSNbxzh/vdSzXZKdWnRlGrPUlF2XGY6HDI', 'Arjun Ashok Jadhav', '+919850470593', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-08 11:32:50', '2025-12-08 11:33:58', 'active', '2025-12-08 11:33:58', 0, NULL, NULL, 1, 0),
(152, 'Pathan', 'Pathanbasheerkhan9@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$NVgwcWY2U21kT3d3MXY0YQ$mBOHSVp5QTo4pd2cRvAkxPF3YbtOcT3hmy/5M3nMTiM', 'Pathan Basheer khan', '+918121366998', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-08 16:40:24', '2025-12-29 10:11:28', 'active', '2025-12-29 10:11:28', 0, NULL, NULL, 1, 0),
(153, 'c1b3rpqd', 'ipinheiro@proton.me', '$argon2id$v=19$m=65536,t=4,p=3$cHJoTUZvTEZkVXM0MzRmag$PehV81hZnmNRvdPVfZzYJooplJqooDS5fsDcD+keYko', 'ivan camargo pinheiro', '61999451336', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-09 01:25:26', '2025-12-09 01:26:22', 'active', '2025-12-09 01:26:22', 0, NULL, NULL, 1, 0),
(154, 'Dhanush', 'dhanukshatriya20@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$dlRickl2T0pZOE5ORzdHWQ$bQiE4+JB/RFxtFPUIWLzgsTuc+Tb8UxnRDX4ejBg1EM', 'Dhanush Dhanu', '+919618673980', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-09 04:43:23', '2025-12-09 04:45:01', 'active', '2025-12-09 04:45:01', 0, NULL, NULL, 1, 0),
(155, 'Gayatri', 'gayatrighadage0408@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$bHVQSTRBcy9VVGNsV3JnMQ$HBzoKpsh6ED4uE81J3HXtVs1b0M2jW+oHeMyNFr78SA', 'Gayatri Vijay Ghadage', '9226218838', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-10 03:09:26', '2025-12-10 03:14:24', 'active', '2025-12-10 03:14:24', 0, NULL, NULL, 1, 0),
(156, 'shreya', 'shreyajagadale111@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$dGl0eW40WHlKM0tLRHVRdQ$TkiDAaNYtFbQpoHGv9MyLqicyCto8DbQ6ekUfsUhRKc', 'Shreya Vilas Jagadale', '7249065563', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-10 03:10:29', '2025-12-10 03:13:31', 'active', '2025-12-10 03:13:31', 0, NULL, NULL, 1, 0),
(157, 'afolabiD', 'afolabidamola20081@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$YXdnRy5FU2tMczBrY3JRQg$V5cAyt+V4fX3ydT9Bf955Ns6cYhP8zTuMsfCwlxXMcM', 'AFOLABI', '07061214386', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-10 10:22:53', '2025-12-10 10:28:30', 'active', '2025-12-10 10:28:30', 0, NULL, NULL, 1, 0),
(158, 'AYATULAI', 'ayatulaiolamide@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$UFVveUVOVERPRERlVHMzbg$iorw8evalBTr9pJeQCPgrVTFqAsQffzBRy4P5Q/qBRU', 'AYATULAI OLAMIDE', '9127938020', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-10 12:57:11', '2025-12-10 12:59:12', 'active', '2025-12-10 12:59:12', 0, NULL, NULL, 1, 0),
(159, 'GreatMitnick', 'usmangreatsuraj@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$MUcwcjVVbTV3QThjVTAzMQ$MffHwRsvOMvs8TsWxaUZn7dgpE9NKwL54gdlQGBHigY', 'Usman Great Suraj', '0814008195', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-11 11:25:12', '2025-12-11 11:26:28', 'active', '2025-12-11 11:26:28', 0, NULL, NULL, 1, 0),
(160, 'Nthabiseng', 'nthabie.lebusa@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$MVdudk8zcmouMnVDMEFRbA$X/GevzGozsyX2bD331i3f7SUCdcEDaUUHUBYxh66nY0', 'Nthabiseng Tsotetsi', '0834369584', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-11 14:16:20', '2025-12-11 14:16:53', 'active', '2025-12-11 14:16:53', 0, NULL, NULL, 1, 0),
(161, 'NinaJai', 'jdmurrayinfosec@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$bjIyZnBJalM1UEQ0Wm9Zcw$quLJz7IZThA21q6nB1CFiZFZ4xYweVunQFPI10yQmS0', 'Julia Murray', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-11 16:25:12', '2025-12-11 16:26:35', 'active', '2025-12-11 16:26:35', 0, NULL, NULL, 1, 0),
(162, 'shirishjagdale', 'shirish.jagdale150892@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$Mi81Q3pDN0FUZzdqeWEvcg$MhdkM+T6y/O3IC0Px75PzTOCwT1eeVv4rvv5ocqWLIM', 'Shirish Jagdale', '+353899837122', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-12 03:09:12', '2025-12-12 03:15:30', 'active', '2025-12-12 03:15:30', 0, NULL, NULL, 1, 0),
(163, 'Likhithreddy123', 'itslikhith596@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$dm9vN0pESU5kTE1LU3hEWA$ptacyu0Zknv/IzfmgimW8gvpIfNDXPqxFSFpTA2IRNo', 'Likhith Kumar Reddy Yeramareddy', '9392513873', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-12 13:53:05', '2025-12-12 13:54:25', 'active', '2025-12-12 13:54:25', 0, NULL, NULL, 1, 0),
(164, 'ffkaburga', 'ffkaburga@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$cUk0cmhma3NaMi55NC44Vg$ZpnmB2Nb17x2Ds3nEHloQEAFWJn2t8Z81yBuRUcfMrw', 'FUAT CAN KABURGA', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-12 17:25:50', '2025-12-22 09:02:43', 'active', '2025-12-22 09:02:43', 0, NULL, NULL, 1, 0),
(165, 'saqi99', 'samirj1999@proton.me', '$argon2id$v=19$m=65536,t=4,p=3$TE1wL2tMWnhvcFlZeFNWcQ$5kZPMFtQRZOdk6swS72jB6uuDCo1UMMi8SUnAwtGGsQ', 'Samir Januzi', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-12 20:03:35', '2025-12-12 20:06:03', 'active', '2025-12-12 20:06:03', 0, NULL, NULL, 1, 0),
(166, '2287333', 'vcharithasree16@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$bmZWYXlVZGZZeEhtelY5Yg$ycLZcPZWVFkY4O+A9k5QmzXj6NCykpTkUgtfn0RecOM', 'v.charitha sree', '8985039672', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-13 16:22:23', '2025-12-13 16:27:16', 'active', '2025-12-13 16:27:16', 0, NULL, NULL, 1, 0),
(167, 'umerazizrana', 'umeraziz786@yahoo.com', '$argon2id$v=19$m=65536,t=4,p=3$NEN4Y0JnRmJQZHFQMTdLQw$AhJJAeH5FDGGa71WCLcDB4ZU0eTgPssLxHKGkGbuiVM', 'umer aziz rana', '+923077224455', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-14 08:16:52', '2025-12-14 08:22:00', 'active', '2025-12-14 08:22:00', 0, NULL, NULL, 1, 0),
(168, 'Minijecca', 'jessica.r.fuhler@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$Y3lvVHJrSnE1VWxlUC85dQ$o2FnaStR9LKE7yW2zJGIVL99A3xqBitUEZykdvejd1w', 'Jessica Fuhler', '9079472015', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-14 13:35:55', '2025-12-14 13:45:01', 'active', '2025-12-14 13:45:01', 0, NULL, NULL, 1, 0),
(169, 'Anand8790', 'pal879026@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$eFNwYU1ZTDNQZ0NLN3BUQQ$ocRQCeEYvTXFh0Jgrene9utnKZePxROYCdIGX0466qo', 'Anand', '+91 9695240278', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-14 14:33:23', '2025-12-14 14:36:41', 'active', '2025-12-14 14:36:41', 0, NULL, NULL, 1, 0),
(170, 'Prasadpanda', 'pjaykrishnaprasad@gmail.com', '$2y$10$.VCFUnnppqZayOECtwd.5uAY9onaFOJInYY5VD9k8Ph6Nn2SOu/8.', 'BHAIRABA PRASAD PANDA', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-16 07:59:23', '2025-12-16 13:14:56', 'active', '2025-12-16 13:14:56', 0, NULL, NULL, 1, 0),
(171, 'SamuelNkanyane', 'samuelheaven@yahoo.com', '$argon2id$v=19$m=65536,t=4,p=3$amp2VkpUYTZuMWFOLzZMTQ$jlbTcSTzP89W7RpJy4cIFkUZX2Kg6aGUozvS9KfoAf4', 'Samuel Nkanyane', '+27729946607', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-17 07:08:51', '2026-01-05 09:22:23', 'active', '2026-01-05 09:22:23', 0, NULL, NULL, 1, 0),
(172, 'Vinayak_007', 'vinayakrudrawar984@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$WVJTdlIuQ3REY1Q3U0l5Zw$bZvPMIazjCRLG+qXrEWeOGmzcAfHo3Ukenc1b5ccK7s', 'Vinayak Rajkumar Rudrawar', '+917058170858', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-17 14:31:49', '2025-12-17 14:32:16', 'active', '2025-12-17 14:32:16', 0, NULL, NULL, 1, 0),
(173, 'Sanika2', 'sanikapokharkar08@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$WkN0TGJsbFovc01xdE5neg$scgxBtCJYEaqpo9n6ooKEw9u5IJ+r8S+7/oV27Xailg', 'Sanika test', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-18 14:20:30', '2025-12-18 14:22:05', 'active', '2025-12-18 14:22:05', 0, NULL, NULL, 1, 0),
(174, 'tekin', 'perezjoe.2022@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$TTFMbkJhS1lkWEtINnUyeg$www7TRsaQw9vqqb9xBe0lQUgAFR6mKMMVfT+lWo6F0k', 'lucas perez', '915122834', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-20 00:34:23', '2025-12-20 00:39:06', 'active', '2025-12-20 00:39:06', 0, NULL, NULL, 1, 0),
(175, 'mrsecurity1', 'akshaymbhat1950@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$dTAxclRsUS80eU9qSDNkSA$cRJM7FmcZAzImeab5LEYNHlbHYcEBJ8pgzkaOSvOwao', 'AKSHAYA M BHAT', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-21 08:59:05', '2025-12-21 08:59:55', 'active', '2025-12-21 08:59:55', 0, NULL, NULL, 1, 0),
(176, 'MHNE', 'rohittoxic792@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$SDNoUS9yaXV2Vk1jNzFtVQ$1rzxsJRJb6G27unId1tuVUW1Va+uSE1IhVqPmc3M6jM', 'MHNE', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-22 15:29:43', '2025-12-23 13:34:58', 'active', '2025-12-23 13:34:58', 0, NULL, NULL, 1, 0);
INSERT INTO `users` (`id`, `username`, `email`, `password`, `full_name`, `phone`, `profile_image`, `user_type`, `email_verified`, `verification_token`, `reset_token`, `reset_expires`, `remember_token`, `created_at`, `updated_at`, `status`, `last_login`, `login_attempts`, `locked_until`, `email_verified_at`, `is_active`, `failed_attempts`) VALUES
(177, 'millerjk24', 'millerjk24@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$Mkh2SVdkMENSSHZqVXJNVQ$3jVvNeDR8QDpfRDhozO1eBsJ8G945szfb9AEuWbVXlQ', 'Jordan Miller', '17654914688', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-23 15:52:28', '2025-12-30 21:47:09', 'active', '2025-12-30 21:47:09', 0, NULL, NULL, 1, 0),
(178, 'Vacky1292', 'vikramaditya.karanwal1412@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$ZXhHZGJiQXNZeTBqNE9sQg$n3szJuckluRpfyZw3rwMt4eOd4MGFO447NWhrqb227A', 'Vikramaditya Karanwal', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-24 11:00:57', '2025-12-24 13:26:57', 'active', '2025-12-24 13:26:57', 0, NULL, NULL, 1, 0),
(179, 'Unlisted4496', 'talles.d.o.p@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$bWt6dllRMXdyMENnRThYMQ$C38R9zU8/2wBw3MfmG7nER+mPAPQarqBBWgxybx3gss', 'talles dantas de o paiva', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-25 06:41:24', '2025-12-25 06:58:41', 'active', '2025-12-25 06:58:41', 0, NULL, NULL, 1, 0),
(180, 'Iswarya', 'iswaryachillukubattula@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$T01wYWI5TlJ6UkVaUlZSeg$pyy/cvLcsDG6Zj5/5n9W6CW1TcARO/ZM11mRaN7ZBGQ', 'Iswarya Chillukabattula', '+917995432050', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-25 12:30:26', '2025-12-25 12:40:18', 'active', '2025-12-25 12:40:18', 0, NULL, NULL, 1, 0),
(181, 'Sumaiya1909', 'syedasumaiyafatima8@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$UlNLNzJTWWhvV3F4c2dPbA$A/pW6DPXcEx48IJ45NWtSWJETMYi/Xev1P2ZdWe38Xo', 'Syeda sumaiya fatima', '8184414050', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-26 02:02:45', '2025-12-26 02:05:41', 'active', '2025-12-26 02:05:41', 0, NULL, NULL, 1, 0),
(182, 'nestorym', 'matanornestory@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$YXV1UkFsTlJ0dVpLWmlpQg$64iAlTNZAmS/Io+3797lcp89RltXhKACn8OsJ0DoLNw', 'Nestory Matano', '+254731527172', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-26 07:50:09', '2025-12-26 07:50:21', 'active', '2025-12-26 07:50:21', 0, NULL, NULL, 1, 0),
(183, 'krishoethicalhacker', 'kris.ho.ethical.hacker@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$L3RGNWtlOXpXNVl5SlRJNQ$75MDrKrv/kUqXPAUgR14KW5SU/O6ZGeGW3tK+YP+pvI', 'Ho Kai Chun', '85293018518', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-26 13:46:26', '2026-01-01 13:04:40', 'active', '2026-01-01 13:04:40', 0, NULL, NULL, 1, 0),
(184, 'dar0', 'dariusz.glogowski@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$OWJEd1dsN3FKWVBVeE1Lag$YxU5BCi0bejCe/TL7wFvYhOlqBALzc/Y1X9L+PF63Sk', 'Dariusz Głogowski', '+48575303363', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-26 20:18:29', '2025-12-26 20:19:44', 'active', '2025-12-26 20:19:44', 0, NULL, NULL, 1, 0),
(185, 'Vaishnavi', '23u0070@students.git.edu', '$argon2id$v=19$m=65536,t=4,p=3$NldRR1JZNFk3TVhXREhCMQ$2/zt5JXPpCd4ed9qeuxQWJQezfxff33xL+tugkhT2zQ', 'Vaishnavi Basavaraj Sutar', '9902302022', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-28 11:49:11', '2025-12-28 11:51:23', 'active', '2025-12-28 11:51:23', 0, NULL, NULL, 1, 0),
(186, 'SandeepDhuri', 'sandeep_dhuri@yahoo.com', '$argon2id$v=19$m=65536,t=4,p=3$LzY3RWpvQS94ak85QXRscw$9dhO3B2uQkmkCJdBpDIgSbaFU/5V8dMYSl53Qd1DqGE', 'Sandeep D Dhuri', '+919223575894', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-29 06:17:55', '2025-12-29 06:19:24', 'active', '2025-12-29 06:19:24', 0, NULL, NULL, 1, 0),
(187, 'chimi', 'sumant9.cyber@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$VWouNjNkaHJQM2FScG1odg$oQ/thQIKuBC0AGR3T5JvLULj3w/RgZ+hGNY5kncBb1Y', 'Sumant Deshmukh', '9322589471', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-29 10:20:31', '2025-12-29 10:22:14', 'active', '2025-12-29 10:22:14', 0, NULL, NULL, 1, 0),
(188, 'nezer', 'ebenreignitstuff@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$SHlsQ2syYmVXdndoL1ptaw$gTgxZIq7pUfUbJAO91ia51fPF+QZt849EKhdhixncTU', 'EBENEZER KRU ADJEI', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-29 12:06:52', '2025-12-29 12:10:33', 'active', '2025-12-29 12:10:33', 0, NULL, NULL, 1, 0),
(189, 'aphadatare173', 'aphadatare173@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$VlQ1ZkpoeDhRV2VQODBqeQ$ra8PUg/OiAN7eD9g8khvvnf0VulzbdskjDcHS54Vh4U', 'Amol Laxman Phadatare', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-30 06:23:57', '2025-12-30 06:31:50', 'active', '2025-12-30 06:31:50', 0, NULL, NULL, 1, 0),
(190, 'ekoyokingsley1', 'ekoyokingsley1@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$akkzZ052ckpabFdUV0hRUw$0u6LgvAUAGMVjxhqTQLBAEr47sMx1B03DB6avFpDPRg', 'Ekoyo Kingsley', '07088980835', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-30 10:16:45', '2025-12-30 10:18:39', 'active', '2025-12-30 10:18:39', 0, NULL, NULL, 1, 0),
(191, 'NJohnwell', 'pntjohnwell47@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$bmNxTkNJaHBJMkd3Nm5KMQ$8Cf61zEauSPoGyPkAQinsSmR0dLv3cY49ISncpQbqEI', 'Newman Johnwell', '+67571991760', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-30 10:41:44', '2025-12-30 10:48:01', 'active', '2025-12-30 10:48:01', 0, NULL, NULL, 1, 0),
(192, 'alijeeshan', 'cyberengineer.it@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$bGtiTVE5dHo3L1ZockRHLw$9lGFaTPXzWnFtROs3n6HG84WHLUMGWlhW0Jcig3u9H0', 'Jeeshan Ali', '8076126387', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-30 11:00:21', '2025-12-30 11:09:08', 'active', '2025-12-30 11:09:08', 0, NULL, NULL, 1, 0),
(193, 'Devendra214', 'soni808577@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$dVZiZnlKdnFIV3hURW5VYQ$mx1jNeVimjF6ZoJW2YtYBp+vYlW42fEk6O6WvuRRwfo', 'Devendra kumar soni', '+918690949517', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2025-12-30 13:22:51', '2025-12-30 13:24:30', 'active', '2025-12-30 13:24:30', 0, NULL, NULL, 1, 0),
(194, 'proggy', 'progrezz23@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$cmtYdXkyQS5wMldCWkJaUA$9FXRrOY44bG95dK76faX46w0QeolaGxIAypoDcWWvlU', 'Progress Ehiemere', '2349018614363', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-01 08:14:06', '2026-01-01 08:17:11', 'active', '2026-01-01 08:17:11', 0, NULL, NULL, 1, 0),
(195, 'Drojev', 'drojev.cybersec@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$ek1oZWgwUm9DNm5JT3VRNA$G0WvujIPSshXd+l5A48CVYnVyVPnAlaiAWIIMcN4+cs', 'Victor Enrique Rojas Damasco', '+51 933417931', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-02 00:21:23', '2026-01-02 00:32:06', 'active', '2026-01-02 00:32:06', 0, NULL, NULL, 1, 0),
(196, 'Naveen', 'nimmanagotinaveen@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$b1djbnJheFZxaXV1Rmk3dA$tRSGZywQRouPTb8ImCYLP2VcZ8fC1RMSUeV/gbWl0t4', 'Nimmanagoti Naveen', '8143575624', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-02 03:51:23', '2026-01-03 03:44:24', 'active', '2026-01-03 03:44:24', 0, NULL, NULL, 1, 0),
(197, 'NPANTOS', 'apantinuraini8@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$VW9Sb0JHMk80RzVPQlk0Lg$kZuUsU6OjPXS54Mjb8FwFNIr2iwkQLTlB35iCAmRrYM', 'Ahmed Nuraini Panti', '08064973825', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-03 12:03:41', '2026-01-03 12:04:39', 'active', '2026-01-03 12:04:39', 0, NULL, NULL, 1, 0),
(198, 'sohail', 'sohailahmed83@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$UE56N1AxL1VKWmxjRnpDZQ$bcJ/Q37/vLNfCVAXiydK9pM+o1BwAT6zwOizsZD3tOA', 'syed sohail ahmed', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-04 05:09:41', '2026-01-04 05:14:00', 'active', '2026-01-04 05:14:00', 0, NULL, NULL, 1, 0),
(199, 'Atulkhanal', 'ATULKHANAL37@GMAIL.COM', '$argon2id$v=19$m=65536,t=4,p=3$d3JoeWZ4UG1zbWYzVGppRA$6NkUGryCABsSrEmyH/v5Ex6k9cM2Qe6wZUVrR6phsT4', 'atul khanal', '+977 9862258069', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-05 04:45:57', '2026-01-05 04:50:14', 'active', '2026-01-05 04:50:14', 0, NULL, NULL, 1, 0),
(200, 'newuser', 'tonori7979@gavrom.com', '$argon2id$v=19$m=65536,t=4,p=3$eFpFbEF1RzdtQXl2all1WQ$2CRjkAvAj4OmCthajiHMAczp5bg9tGJKgoUjkRrxfpo', 'New User', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-05 06:40:40', '2026-01-13 10:35:01', 'active', '2026-01-13 10:35:01', 0, NULL, NULL, 1, 0),
(201, 'pratham', '230610107027@gecpalanpur.ac.in', '$argon2id$v=19$m=65536,t=4,p=3$c3JVUFNUay95OUt4WmI0bQ$uebO4KEoo8xwl2l/b43LWvINv7zVxjCRKlA9ZWHRPE4', 'pratham parmar', '9427512951', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-05 13:11:38', '2026-01-05 13:13:50', 'active', '2026-01-05 13:13:50', 0, NULL, NULL, 1, 0),
(202, 'captain95632', 'captain95632@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$L2RqOHN4MlFlZVVjbFBmbg$9b3pH5pGQCsdnyfbKo7kiXp8McknEsR2sGP1gWWVmb4', 'captain levi', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-06 07:08:38', '2026-01-06 07:10:36', 'active', '2026-01-06 07:10:36', 0, NULL, NULL, 1, 0),
(203, 'Santu', 'santhoshmani7703@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$ckdtN3lmekRwUTNseGNicA$oBULb/XjcQglDC7wzOfIlCSxwkvBCKmYpwcPn0xQNgU', 'Santhosh M', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-06 09:32:24', '2026-01-06 09:41:35', 'active', '2026-01-06 09:41:35', 0, NULL, NULL, 1, 0),
(204, 'gps', 'gagus.pedrozo@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$a0NyS00zWjBsLnRDSzU3Zw$LlJoCpNNw90S/d72uFUOjXVgxC7PXhDi76IkhTfwe2Y', 'Gabriel A. Pedrozo S.', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-07 04:36:45', '2026-01-07 04:37:20', 'active', '2026-01-07 04:37:20', 0, NULL, NULL, 1, 0),
(205, 'aishwarya14', 'aishwaryamani.1991@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$SXByN2o5OHFoMXRGL0lBbA$KoRe7a/7HIni27/OutOIzdDxztn6o9XYFN7JcOtcbFE', 'Aishwarya Subramanian', '+4916098254339', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-07 13:18:19', '2026-02-08 14:16:56', 'active', '2026-02-08 14:16:56', 0, NULL, NULL, 1, 0),
(206, 'yules', 'yulandatross.np@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$Q0U2U1RWMkxSeUZVYy5XUQ$SeOFW5sKMLAh8x+ijjzSixjsR8PF0Q+MDs7ScWO1HOQ', 'Yulanda Tross', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-07 17:48:54', '2026-01-07 17:50:47', 'active', '2026-01-07 17:50:47', 0, NULL, NULL, 1, 0),
(207, 'jonathanmorgan83', 'Mr.Jonathan.Morgan@outlook.com', '$argon2id$v=19$m=65536,t=4,p=3$NFBUYWZodlNhMG9ITy5GSw$p+DJpueFMFxF27gXBcmqqTKrealknxGBxh0Zo9blBu8', 'Jonathan', '15406550568', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-07 20:48:56', '2026-01-07 20:50:42', 'active', '2026-01-07 20:50:42', 0, NULL, NULL, 1, 0),
(208, 'mohdnoor', 'mohdnoor.siddig@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$R2hYbHo4ZGF6RlppMmk4TA$/nD5SsQRQQseYro1JOhDKZ2Ex+kpaGaE63IcRQrXnUg', 'Mohammed elnour  siddig', '00971556969045', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-08 08:16:42', '2026-01-08 08:34:59', 'active', '2026-01-08 08:34:59', 0, NULL, NULL, 1, 0),
(209, 'Calabras122', 'narwaderitesh2005@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$NldTMEdFQy5RLzd2QlJqZQ$PIZhwd/r/otEGorlBPFq7Edk1N47rlnOk2XXNww2bRM', 'Ritesh Rajesh Narwade', '7276084538', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-08 14:08:17', '2026-02-04 08:29:57', 'active', '2026-02-04 08:29:57', 0, NULL, NULL, 1, 0),
(210, 'Arun', 'arunyuvaraj5670@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$RzhLTUE2ZjVzS3VZNEZZNQ$OV6U2tFhCld5YW3XYDxpOmyMQbPeGGLlPMgsm5SQRyk', 'Arun Yuvaraj', '+919445904432', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-09 04:58:31', '2026-01-09 05:17:54', 'active', '2026-01-09 05:17:54', 0, NULL, NULL, 1, 0),
(211, 'zafar0701', 'ZAFAR0701@YAHOO.COM', '$argon2id$v=19$m=65536,t=4,p=3$WGJ3RWxxTnRUbnUwSEhHYg$T9AVaMx8CNPkuohQYWspeUDMnT4dXtLi8274dBAn8Kw', 'Mohammed Zafar Imam', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-09 06:59:43', '2026-01-09 07:01:26', 'active', '2026-01-09 07:01:26', 0, NULL, NULL, 1, 0),
(212, 'zemed', 'zemedabeje52@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$ZGtrT3UyVnNoSTR0ZHRubg$id7QjKgWfRIP0VMzcRTI9D/FNUQbqI+Zj6IpPKHleW8', 'Zemed Abeje', '+251956123417', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-09 11:12:24', '2026-01-09 11:17:49', 'active', '2026-01-09 11:17:49', 0, NULL, NULL, 1, 0),
(213, 'Naviya_98', 'blnmwije@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$U0k1TUt5bkVhZTguUURjQg$yUiHzOiIrMEEVTwoUL5Sj1+e1D0RgZu8UYWw6XcsybI', 'Naveen Wijesinghe', '+94710867204', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-09 14:16:48', '2026-01-09 14:18:53', 'active', '2026-01-09 14:18:53', 0, NULL, NULL, 1, 0),
(214, 'shinqitee', 'shinqitee@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$czNHZlp6R1hSNnIzWVN5aA$MzU5/8t71RIDqem65x9+VBZRPXL13FbH1lim0/YXxTE', 'Mohammed Amin Saeed', '+233207598643', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-09 14:18:12', '2026-01-09 14:18:42', 'active', '2026-01-09 14:18:42', 0, NULL, NULL, 1, 0),
(215, 'shajukumarnimmakuri', 'shajukumarnimmakuri@zohomail.in', '$argon2id$v=19$m=65536,t=4,p=3$SGdDaXhsMlpXcktvSVBYZg$La7HicYwZJLD+U4g2CkhhnhaHrJfbRXvEVizcf7b530', 'Nimmakuri Shaju Kumar', '+919652500086', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-09 15:27:59', '2026-01-09 15:34:29', 'active', '2026-01-09 15:34:29', 0, NULL, NULL, 1, 0),
(216, 'Muneeb_Ahmed', 'ahmedmuneeb812@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$ZU5PRUx3aGxBbDlLUnJBaA$Je7XoO5/NwM9Qx5X+djTnQbaye9gKUFERlYXBVDtHVo', 'Muneeb Ahmed', '03485363620', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-09 18:48:31', '2026-01-10 20:08:47', 'active', '2026-01-10 20:08:47', 0, NULL, NULL, 1, 0),
(217, 'Little_08', 'vasavisrilekha.g@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$UUcvWUZyY0pxcUhMcmUvRg$Af4HsmJOQsCPvSqmUKOR1h7sOhHpgzEU4sETvjiTuNk', 'Vasavisrilekha', '8565267548', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-09 18:59:43', '2026-01-09 19:02:01', 'active', '2026-01-09 19:02:01', 0, NULL, NULL, 1, 0),
(218, 'AmjadSharif', 'amjadsharif19@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$VVRXQ1VFOVpWNnc0WU9GdA$O1Di3pYzfBs9cbVkZfjULZEWgWWlVXpnQYFWplRN1IU', 'Amjad Sharif', '9790863390', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-10 13:41:22', '2026-01-10 13:41:22', 'active', NULL, 0, NULL, NULL, 1, 0),
(219, 'sithik25', 'sithikali2000@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$TGVLMkw1Q2ZMbW5sOUpCRw$B5ToUBUsljtdt1hEWBge7B5QwDZgAdUIWovU9bvTVSY', 'MOHAMAD SITHIK ALI F', '+918940542016', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-11 06:43:42', '2026-01-11 06:47:26', 'active', '2026-01-11 06:47:26', 0, NULL, NULL, 1, 0),
(220, 'Babul2139', 'ariantalukdar7@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$VkFPalFXWmZjSjhqLzFPQg$zp/3uR965V9RLBQUc64r/8jBI55XO3d/8sSkbObdVKQ', 'Shahan Uddin Babul', '+39 3296437742', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-11 09:13:06', '2026-01-11 09:16:24', 'active', '2026-01-11 09:16:24', 0, NULL, NULL, 1, 0),
(221, 'nizar', 'nizar1webdesign@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$TDR6RFBrQ1cwcTIudjdlLg$KqS03fKwlsVkO5ZdL7ynBT1kdzB5YHKzd9ta1CIRMMQ', 'Nizar', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-11 11:18:06', '2026-01-11 11:18:42', 'active', '2026-01-11 11:18:42', 0, NULL, NULL, 1, 0),
(222, 'SriHalya', 'halyasri55@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$RTVlU3paLmNld3BCaURoYg$RQazgkKPZahr42kz9DhLmY2yi9d3J0+223Lls7LSzU8', 'A. Sai Sri Halya', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-12 05:58:16', '2026-01-12 06:03:11', 'active', '2026-01-12 06:03:11', 0, NULL, NULL, 1, 0),
(223, 'mobilecyberd', 'srksianx@rulersonline.com', '$argon2id$v=19$m=65536,t=4,p=3$OXFQMkNidGU3M2hUbWRVNA$MyZMk2QRsWzoe/iDfLAiOL72K6VgJBVVYL5SloMdKfk', 'fsafdsa', '8059617232', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-12 10:10:25', '2026-01-12 10:10:25', 'active', NULL, 0, NULL, NULL, 1, 0),
(224, 'test', 't3f77@virgilian.com', '$2y$10$o.UX9HjyfNPpTfa5Ygy4MOdmB2KI/6k.hTBw4TulTiOTOqvaXIFDe', 'amit', '8059617232', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-12 10:19:11', '2026-01-12 10:35:42', 'active', '2026-01-12 10:35:42', 0, NULL, NULL, 1, 0),
(225, 'test1', '5i7i0@virgilian.com', '$argon2id$v=19$m=65536,t=4,p=3$SVRleGhxT0hXUDZtTkV2Nw$QrdB/N+g4i6TAGOmSsBa3pX+fev25EVs4cdc0L6b2Nc', 'amit', '8059617232', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-12 10:23:50', '2026-01-12 10:30:58', 'active', '2026-01-12 10:30:58', 0, NULL, NULL, 1, 0),
(226, 'TANGO1988', 'tawheedwani88@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$R3hscmhMenVWLk9TR09tRw$9y3Av0qUOBqmZRHfKSgOC5kPfCskrpBWW+SVKhMiyZE', 'TAWHEED AHMAD WANI', '9622461447', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-12 17:51:34', '2026-01-12 18:02:08', 'active', '2026-01-12 18:02:08', 0, NULL, NULL, 1, 0),
(227, 'mukhii', 'mukeshamiti005@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$U1BNd1FLY0VLd0lvb0JVNw$f/xfxE8CSYH3WDiLJMuhY/iZdgloxrYetMzHf4sf0WE', 'Mukhesh amiti', '9381875582', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-13 14:35:33', '2026-01-13 14:36:07', 'active', '2026-01-13 14:36:07', 0, NULL, NULL, 1, 0),
(228, 'cypher', 'harshpatidar1003@gmail.com', '$2y$10$MM/0d3ZjxpUGR2tJyWdXBOJQbIWGBm/RRb1dtV1Az/d60/9E7YvDC', 'Harsh Patidar', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-14 03:48:54', '2026-01-28 07:57:45', 'active', '2026-01-28 07:57:45', 0, NULL, NULL, 1, 0),
(229, 'hashimi414', 'smhashimi0310@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$N0t1UThZUFpmU0lzLksxYQ$0zSRami5H1nxRQ4wyVwgf0atVSzQFtTBPDb1w+Y4wik', 'Sayed M Hashimi', '8457419225', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-15 17:08:10', '2026-01-15 17:16:34', 'active', '2026-01-15 17:16:34', 0, NULL, NULL, 1, 0),
(230, 'SonaliSalgar123', 'Salgarsonali99@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$ZUEvRkgyaGJGV3NTYnB1Mg$atlMafPyfE8CM0/LqORI1n8MXI1Mc4CI3FZ4jVqDj1w', 'Sonali Chandrkant Salgar', '+919011004033', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-16 06:57:27', '2026-02-02 10:40:15', 'active', '2026-02-02 10:40:15', 0, NULL, NULL, 1, 0),
(231, 'aravindgopalakrishna46', 'aravindyoyo@outlook.com', '$argon2id$v=19$m=65536,t=4,p=3$UHlDRmJNdkJvbmdPUUFDTw$4Ua0eMJFe+aCo42o1rM2LMUEShxmiNvXtZMPHxjb39A', 'Aravind Gopalakrishna', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-16 09:45:42', '2026-01-16 09:50:00', 'active', '2026-01-16 09:50:00', 0, NULL, NULL, 1, 0),
(232, 'Narasimha22_4', 'nikenduku9966@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$SWhEQ2ZEYU5Cd1Z2NTNNTg$qbdCT4fzvEZLWUknf4nCSiRsjKpoqLf0dozq1Sehsss', 'Sunkara Lakshmi Narasimha Naidu', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-16 10:44:53', '2026-01-16 10:46:11', 'active', '2026-01-16 10:46:11', 0, NULL, NULL, 1, 0),
(233, 'siddharth_singh', 'siddharthsingh.azr@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$VGxyeUtCYmJIWXN3OFZHSg$5qKMELy22J3SHoiQxCcwJDWbeX+8rsfYXGkrSarALAU', 'Siddharth Singh', '6386497600', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-16 12:45:38', '2026-01-16 12:46:11', 'active', '2026-01-16 12:46:11', 0, NULL, NULL, 1, 0),
(234, 'omkargavali00', 'omkargavali2006@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$MUhxYllTRGhudjQ3ZkpBcg$c+gyhbC6gPJBDo5YtuzNbBTXBfvEs7tkmuvPEb4PSKM', 'OMKAR GAVALI', '8624932390', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-16 15:44:36', '2026-01-16 15:45:52', 'active', '2026-01-16 15:45:52', 0, NULL, NULL, 1, 0),
(235, 'zartharas', 'smart.joe01@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$MUlkeXBNZGRHWjdKZmh0eQ$C6YysEGQ95I9H82NN10nxRL1rfbTcw458QVLwf5c5pQ', 'Aman Singh', '475-222-3744', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-16 16:47:38', '2026-01-16 16:47:57', 'active', '2026-01-16 16:47:57', 0, NULL, NULL, 1, 0),
(236, 'niulaxan', 'nilaxanathas271297@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$Q0FqWVl4amQyRVNjeVRWbw$+715TkX4+g5W8Vf2GIADHAoYDjw59YLWaoeE/Ds3wdg', 'Samithamby Nilaxanathas', '+447466889939', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-16 21:41:14', '2026-01-16 21:49:36', 'active', '2026-01-16 21:49:36', 0, NULL, NULL, 1, 0),
(237, 'kapilbisht', 'bkapil978@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$dDdMc25OTjRiM1dXSXBJVw$Ddk24D+CREMqRtaElwEexrQvJ5NJJYOzIilKGkm8KbQ', 'kapil bisht', '+918954258812', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-17 15:02:02', '2026-01-17 15:09:30', 'active', '2026-01-17 15:09:30', 0, NULL, NULL, 1, 0),
(238, 'Itzumaz', 'umaropeyemiazeez@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$WWJibEJITVpXeWEyY1ZlLg$a9sUhpbMBBq/tq3+LyYszdb1v8hT7GsuELey21AsEtM', 'Azeez Umar Opeyemi', '+2349117217279', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-19 06:23:45', '2026-01-19 06:30:13', 'active', '2026-01-19 06:30:13', 0, NULL, NULL, 1, 0),
(239, 'ombarot', 'raothomas44@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$WGl5RWguV29NU3Rxd3RVag$DXSveCEUGuf3cuiWIaYuwQVzxyYAUEz10Dxhr0aiOqw', 'Om Barot', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-21 13:01:07', '2026-01-21 14:51:24', 'active', '2026-01-21 14:51:24', 0, NULL, NULL, 1, 0),
(240, 'bsamru', 'bsamru31@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$Q0d5ZTQuSWZ5SFpBRHVtaQ$5vzgRKYz8cxslaNHpTL6EAmZvLNmFI1rvRkvVQz1Px0', 'Samrachana Baral', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-21 13:52:10', '2026-01-21 14:03:36', 'active', '2026-01-21 14:03:36', 0, NULL, NULL, 1, 0),
(241, 'ombarot1', 'llombarotll@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$V3pTdldQMEtJSkdtamFLQw$1NKQqYLya7RE5AunS9dp4S/6AqwqCZ3wPp+NE+wv7yA', 'Om Barot', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-21 14:53:53', '2026-01-30 11:33:10', 'active', '2026-01-30 11:33:10', 0, NULL, NULL, 1, 0),
(242, 'nitishgowda', 'nitishgowda1581999@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$SER6bDJLUHp4c2FEeXlhSg$xK/ySkotjltB45HXrjZ3p3PvVD4iIJrHTYi+LE8Qw0k', 'NITISH GOWDA G', '+917026770076', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-22 06:39:11', '2026-01-25 02:07:33', 'active', '2026-01-25 02:07:33', 0, NULL, NULL, 1, 0),
(243, 'Vaibhavgulati', 'gulativaibhav10@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$czh6VGU2akU4VTNha2txVQ$btDrf/WX7ra+dWw8iXx1FQHXUL07RV3PJ5WqqXRkvno', 'Vaibhav Gulati', '8750585560', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-23 08:14:23', '2026-01-23 08:18:27', 'active', '2026-01-23 08:18:27', 0, NULL, NULL, 1, 0),
(244, 'Saint', 'tiwarianuj3231@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$YWRjVG1jdng0VUZYbUVoMQ$XyxUus7i2wnCsJGSEaUIDL7l7j5dmWOE9cEQ31CCSqA', 'Prashant Tiwari', '7355060044', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-23 08:23:38', '2026-01-23 08:25:32', 'active', '2026-01-23 08:25:32', 0, NULL, NULL, 1, 0),
(245, 'adityasasikumar', 'adityasasikumar422@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$LldhakNxYlFqcmtlYXpHRg$UzfEzHenuKDZfbkmECzQ7PeD9OhYEusgEKdlhD6P4Y0', 'Aditya Sasikumar', '+916383577593', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-23 08:57:55', '2026-01-23 08:58:20', 'active', '2026-01-23 08:58:20', 0, NULL, NULL, 1, 0),
(246, 'Muhammad_Ejaz', 'muhammadejaz.tech@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$UmwyaXk3bTRyOVd4dTg5Vw$WAZq2/nh0gsfQWbD/IL6i3L7eVA2qV0mCvX8Ge3sql0', 'Muhammad Ejaz', '03400492575', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-23 09:26:05', '2026-01-23 09:26:52', 'active', '2026-01-23 09:26:52', 0, NULL, NULL, 1, 0),
(247, 'adk_ashu', 'cybersolo2020@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$VnJVYWRJMzVOTmhkSlFuVw$3xrnkVQ+DC9/GjyH7+FQJULFMX/GqEVOgWXzIMJtL2M', 'Ashutosh Adhikari', '+977-9867288584', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-23 13:30:03', '2026-01-23 13:34:07', 'active', '2026-01-23 13:34:07', 0, NULL, NULL, 1, 0),
(248, 'hafizrajpoot', 'hafizrajpoot.dev27@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$NFc0a05sVW01ZWE2TVhrYQ$9kKi7bKC+48/P4JPgI3NFwZtRFPXSX/L+0DKV/jcOOs', 'M Usama', '+923016062167', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-23 14:37:48', '2026-01-23 14:44:07', 'active', '2026-01-23 14:44:07', 0, NULL, NULL, 1, 0),
(249, 'elomari152', 'elomari.fatimaezzahrae2002@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$TXc3NFlTb3JnYjMvUWhLVw$eo7iRgJBqvbaZsFnsBqhrvXjF1pOREORFPTukCZ/9+U', 'Fatimaezzahrae el Omari', '+212601350651', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-23 15:38:28', '2026-01-23 16:43:23', 'active', '2026-01-23 16:43:23', 0, NULL, NULL, 1, 0),
(250, 'Oshtree', 'oshtree@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$N2tMaTdLTHVVSkRaaGFpQQ$e8u+EedigB2HAdC3WG0WCbA1JBn59RBqU/t9TDv84+s', 'Uros Ljesnjak', '+381653224872', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-23 16:59:07', '2026-01-23 16:59:32', 'active', '2026-01-23 16:59:32', 0, NULL, NULL, 1, 0),
(251, 'Vibe', 'vibevenom009@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$Yk4vUGhlaFQzaWZnZERMSQ$Mtqc4eAg1+m8qQBY5SuUqJpX0C+6Dxsluvi1qFP/PvU', 'Vibe Venom', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-23 18:51:41', '2026-01-23 18:53:05', 'active', '2026-01-23 18:53:05', 0, NULL, NULL, 1, 0),
(252, 'Hassan', 'hassanrana80808@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$aUdrSHdtMWVFWEJaZW1PcQ$L8nqEAGKzQ5CRHPxfiAXd9jpxb91dckChi7FzAsWWZ4', 'Muhammad Hassan', '+923241924514', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-24 05:27:20', '2026-01-24 05:29:08', 'active', '2026-01-24 05:29:08', 0, NULL, NULL, 1, 0),
(253, 'Koushika', 'rkoushika22@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$bnRWSHZHWUY5NWNkT3NpYw$cEZPe9E2YWI+UwpF5REwaxkds3kAyOmX2bRDMyiK3VQ', 'Koushika R', '9994967100', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-24 06:13:43', '2026-01-24 06:16:17', 'active', '2026-01-24 06:16:17', 0, NULL, NULL, 1, 0),
(254, 'TEJASWINIKAMATH', 'tejaswinikamat23@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$bHRELkp0YTlyZUhsQ3VtRQ$riHOqHotjyvNh25nBJLEtod5toJL52ofDLGhFNKmVrQ', 'TEJASWINI VINOD KAMATH', '8296469709', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-24 07:22:38', '2026-01-24 07:37:42', 'active', '2026-01-24 07:37:42', 0, NULL, NULL, 1, 0),
(255, 'MuhammadFarooqTariq', 'farooqtariq211@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$cjI5MU5mYlNkUmF0V3pwaQ$wsMejrlBoz2z/hz9dQFOuh/W/eT8nJuE9FQ7WVH5wSw', 'Muhammad Farooq Tariq', '03272128814', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-24 09:20:35', '2026-01-24 09:22:12', 'active', '2026-01-24 09:22:12', 0, NULL, NULL, 1, 0),
(256, 'fredyhcr1', 'fredyhcr@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$YWtXOFlBYzB2TndIbUJ0cQ$+IW+SY8aKh7jIyUZkUfeh0zwgFELMq/svD0I3Xx/eEg', 'Freddy Hernando Casas', '3214104969', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-25 18:07:17', '2026-01-25 18:07:51', 'active', '2026-01-25 18:07:51', 0, NULL, NULL, 1, 0),
(257, 'Cyber1', 'zipodergeekserver@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$Tnc5NHouSDlaVnp5cmNXRg$bFPTiCtuJ22HxTdtJyaYDurOReQ//0VLi0eLUDbRxlw', 'Cyber Guard', '+25767514585', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-26 07:59:05', '2026-01-31 14:58:16', 'active', '2026-01-31 14:58:16', 0, NULL, NULL, 1, 0),
(258, 'Ibudoayomi', 'onibudo.ayodele@yahoo.com', '$argon2id$v=19$m=65536,t=4,p=3$OTBFVDVPSlp4N1VOSzdiTQ$W7fySxM5uTCBbHtbS5nUFvZnVFvI4M2W5m2TDGUkqz4', 'Ayodele Michael Onibudo', '+4208038400044', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-26 14:04:05', '2026-01-26 16:30:49', 'active', '2026-01-26 16:30:49', 0, NULL, NULL, 1, 0),
(259, 'carlitostic', 'carlos.ticona@outlook.com', '$argon2id$v=19$m=65536,t=4,p=3$ZmlFME43NmpJS3ZxRXJ6YQ$Ej+VszkM9sIRX+oT3KxrQNoJrEloN2+2Fk2AotUW+Zg', 'Carlos Angel Ticona Condori', '+59170520317', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-26 14:58:17', '2026-01-26 15:00:09', 'active', '2026-01-26 15:00:09', 0, NULL, NULL, 1, 0),
(260, 'cwl_krishnak4', 'v4ukrishna@hotmail.com', '$argon2id$v=19$m=65536,t=4,p=3$c29zWDV3d1FBR1VCSFplaA$KW9bAFPiK1WdbNnH3v7kRcQNe3qdAlx4I3RFt+oQ3CI', 'Krishna Kumar M', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-26 18:22:21', '2026-02-08 14:38:43', 'active', '2026-02-08 14:38:43', 0, NULL, NULL, 1, 0),
(261, 'jyothipriya', 'jyothipriya0811@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$SU1UZDhzbmgvd3VmSDNEQg$8DOGA85AyQT8Ep4K5PsQq86MAkyKhXVvPOGIwGIP8iM', 'Jyothi Priya', '+917093973348', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-27 14:17:00', '2026-03-02 06:41:42', 'active', '2026-03-02 06:41:42', 0, NULL, NULL, 1, 0),
(262, 'yuminex06', 'yuminaeliascossa@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$c0dINjl1Q2FNbU5ObXE4RA$SDxT1mfiV7A5iVrp1k2xwCqgVFkfquiQpmw5nbjEjqI', 'Yúmina Elias Cossa', '+48577600419', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-28 04:50:00', '2026-01-28 04:51:42', 'active', '2026-01-28 04:51:42', 0, NULL, NULL, 1, 0),
(263, '12345hacker', 'sigmakidsigmakid123abcd@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$MkJCYzd3Yy9LQ2lJOWN5TQ$BiTidXY9sSxaxn9htcWbgcm82hyt6m4PjxuOeFrJK90', 'Sigma', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-30 03:51:07', '2026-01-30 03:54:29', 'active', '2026-01-30 03:54:29', 0, NULL, NULL, 1, 0),
(264, 'darpanregmi', 'darpanregmi2059@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$ZG80Z1NrQmFiSm9XTFA1Sw$raTGPM7ovTeMZdMqcEK1ycIsNwlFN6IQ2+oUAFkRsJs', 'Darpan Regmi', '+9779869706456', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-30 10:30:49', '2026-01-30 10:33:15', 'active', '2026-01-30 10:33:15', 0, NULL, NULL, 1, 0),
(265, 'McRae', 'charlestankoisaac@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$U042UlZjYmlES1dpRm9CNg$YUU643aCP3VMgpckVkkJOS2Lxv+R9bNPqlVCxQM24/Y', 'isaac charles', '+2348100979272', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-30 10:55:59', '2026-01-30 10:57:06', 'active', '2026-01-30 10:57:06', 0, NULL, NULL, 1, 0),
(266, 'ajanthan', 'ajanthan200002@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$dnJuYzVNenVBcWJZU0Z6Lw$e+pk2UAheaQBitie4Ve257Flk64b94mR0PhNpDtIPFo', 'Amuthalingam Ajanthan', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-30 12:41:29', '2026-01-30 12:44:29', 'active', '2026-01-30 12:44:29', 0, NULL, NULL, 1, 0),
(267, 'anjalmanmathan', 'anjalmanmathan2003@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$SnJ4dmdaSVJsT1ZROVFsWA$stDmIjvXjumFzqaxzA9t2PPZSrPGlcXiJFRYfVunwIU', 'Anjal Manmathan', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-30 15:34:16', '2026-01-30 15:34:42', 'active', '2026-01-30 15:34:42', 0, NULL, NULL, 1, 0),
(268, 'Ban35', 'alabibanjo2@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$TWJHRUxzNlBqamRQTDVCcQ$2TryugtBNM0u7P+Hrkit2jccGMY4t4S/t0MUJv57qFw', 'Banjo Alabi', '+2347068901643', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-31 07:42:07', '2026-01-31 07:49:28', 'active', '2026-01-31 07:49:28', 0, NULL, NULL, 1, 0),
(269, 'Cyberwar26', 'webdigimar24@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$VTFZNVowWnNiOU4vVHc5Zw$QQaxzCs8ilcWgmrSVWXeLHksrwjS09I17nTNsUkZtbU', 'Pratham Rajput', '+918602943068', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-01-31 15:38:07', '2026-01-31 15:38:34', 'active', '2026-01-31 15:38:34', 0, NULL, NULL, 1, 0),
(270, 'UNLUS190519', 'sabanunlu33@hotmail.com', '$argon2id$v=19$m=65536,t=4,p=3$U2lReTRNcWVzZTUyaGZkeA$FwQQrf+9RVbJfR4OOo1qQLyzMPy3eEDw9wUu3fiZXQw', 'ŞABAN ÜNLÜ', '+905395514285', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-02-02 12:36:15', '2026-02-02 12:36:15', 'active', NULL, 0, NULL, NULL, 1, 0),
(271, 'Dragonfist01cricket01', 'abdullahibrahimnowjobwork01@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$WngvN3Q5T1NUM2FhdGx6TQ$1ZNGy0UdnbtFwmeL7mrKOJvJL7TLnqV/H1gKb5ER10o', 'Abdullah Ibrahim Khan', '+8801306440428', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-02-02 13:14:29', '2026-02-02 13:15:44', 'active', '2026-02-02 13:15:44', 0, NULL, NULL, 1, 0),
(272, 'JMT777', 'seventy777jmt@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$RmhQdy9VOTZjNWFxV3plRA$w0WymgY2Zz19RhnbuBMOTLDSWCfUrLHqD4B6MyOQkfc', 'Jairo Mayorga Torres', '61649498', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-02-03 03:48:25', '2026-02-03 03:57:25', 'active', '2026-02-03 03:57:25', 0, NULL, NULL, 1, 0),
(273, 'navinpal1234', 'naveenpal2608@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$T1JWTXBmZFBjS090T243MA$BD0vqEfivEag69bvuoe5r0cO74N0hd/pTu9nfxRL1Uk', 'naveen Pal', '+91 93117 81975', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-02-03 14:56:48', '2026-02-03 17:52:50', 'active', '2026-02-03 17:52:50', 0, NULL, NULL, 1, 0),
(274, 'chikaranam', 'chinnarao.k97@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$Y3A5YTd1Vk9Ib2xBcHloSQ$nKCabZLnhjUKgK/RqOtFbr7C0NcliLKZPlIkv9IcwDw', 'KARANAM CHINNA RAO', '9493627073', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-02-04 08:24:53', '2026-02-04 08:35:07', 'active', '2026-02-04 08:35:07', 0, NULL, NULL, 1, 0),
(275, 'sushantrawat', 'sushantrawat023@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$ZHdubUFnTk9NZjlrVi44OA$jMCSSLsIrpeccamvWrWh3/KQFdgDa9FHHc+3aVOqsJQ', 'Sushant Rawat', '9748708754', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-02-04 18:38:41', '2026-02-04 18:40:25', 'active', '2026-02-04 18:40:25', 0, NULL, NULL, 1, 0),
(276, 'said', 'qarazadeseyid1122@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$ZDVYdWd4OHI4cnNFWUo5aw$xbBegNFcm3S6W0WoZ5yDXQd/kNju2KNYaUiWJM39CJs', 'Said Garazade', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-02-06 15:13:52', '2026-02-06 15:14:37', 'active', '2026-02-06 15:14:37', 0, NULL, NULL, 1, 0),
(277, 'divyanshtank', 'tankm3011@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$ckxyVS9TLjBtU3JzdkIyWQ$Yk9ASWEiXG92P3MySXFlh+fznGBpbACMeH5Te76y3zA', 'Divyansh Tank', '7879727693', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-02-08 13:27:02', '2026-02-08 13:29:32', 'active', '2026-02-08 13:29:32', 0, NULL, NULL, 1, 0),
(278, 'tester', 'tczmibla@wp.pl', '$argon2id$v=19$m=65536,t=4,p=3$eXZVRGZla29XZlFrRjJrQw$+ShSHDaLJBNPrutXyK3y8GQ787VPQeCsFNSsSXyn9Jk', 'testerka', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-02-08 21:58:24', '2026-02-08 22:13:22', 'active', '2026-02-08 22:13:22', 0, NULL, NULL, 1, 0),
(279, 'ginagroce', 'ginagroce3@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$OWxGb3lUWGRmdUN0RVc4Zg$kj3xIUUbWO6+xeNSbDmE81WmioqUcId3XI1/bNvsYWc', 'Gina Groce', '+1 270-507-2620', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-02-09 00:50:04', '2026-02-09 21:18:26', 'active', '2026-02-09 21:18:26', 0, NULL, NULL, 1, 0),
(280, 'dhatriksujan', '112233sujan@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$LlRidlVmWG5BWGxJWnlZVA$vH7tMcGpzXQu5VAERR5ZqfSVI1iaQB488o3aOk5djlE', 'Dhatrik Sujan kumar', '+916302089909', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-02-09 05:41:27', '2026-02-09 05:42:12', 'active', '2026-02-09 05:42:12', 0, NULL, NULL, 1, 0),
(281, 'soujanya', 'soujanyakaradakal@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$OXVnUlNabW9lY1JvNWM5Tg$S7lXxu5p/SdIgHziawZOiUHU987Bbq/T/2jOXSOM/H0', 'soujanya karadakal', '9035050155', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-02-09 07:31:54', '2026-02-09 07:38:14', 'active', '2026-02-09 07:38:14', 0, NULL, NULL, 1, 0),
(282, 'Jerv', 'jervisa88@gmail.com', '$2y$10$Vw/JP5jLPWWT.7HP1a5mau4BcLxAKXVj0eCZsjb98JHjGwRkVQTHS', 'Jervis', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-02-09 07:55:37', '2026-02-09 08:02:10', 'active', '2026-02-09 08:02:10', 0, NULL, NULL, 1, 0),
(283, 'Medhanidhi', 'ymedhanidhi55@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$NGNCai9PT2dSOS5ra0NweA$KqCjeH8zFKxxcU4SHmnEUD/wQK3TpdEzuMRiCyzqq6g', 'Medhanidhi Yedla', '+23057195427', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-02-09 10:44:52', '2026-02-09 10:49:19', 'active', '2026-02-09 10:49:19', 0, NULL, NULL, 1, 0),
(284, 'Abdelaziz', 'benchamekh.abdelaziz@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$di9QZ0RBZDBKNWd3SWJhWg$dLsajzvOIWXL//3ptj5aN0oltR5cWaUU4YuvwG7sNo4', 'Abdelaziz Ben Chamekh', '+79111396496', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-02-10 14:26:16', '2026-02-10 14:27:33', 'active', '2026-02-10 14:27:33', 0, NULL, NULL, 1, 0),
(285, 'tecnomayur7', 'tecnomayur7@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$dUEzVFdLYVZvQU9DM3k0bQ$7HbGeC6Cy2uh6ur6EA2P/4J9qjgoVbNvnsbCe3QVneQ', 'Mayur Girase', '9022458605', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-02-11 08:48:03', '2026-02-11 08:54:47', 'active', '2026-02-11 08:54:47', 0, NULL, NULL, 1, 0),
(286, 'Daved', 'daved4597@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$eXlqS2FZcmMxMFJvUk5WNQ$s+ZOns3fBdu1rklfA4NFUC7pK/6wlWzX8R9J19Uhjb8', 'daved', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-02-11 19:20:06', '2026-02-11 19:49:22', 'active', '2026-02-11 19:49:22', 0, NULL, NULL, 1, 0),
(287, '_Phantom_Snake_', 'nattasit589@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$azR2Rmx2ZlNrUHBMaWxKaw$NPcdPaL46iE0UwJUNOIzoSFwTJ5MffrF9R8iVGPnDIs', 'Nattasit Sanguantanakorn', '+66846282977', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-02-12 00:44:30', '2026-02-12 00:45:01', 'active', '2026-02-12 00:45:01', 0, NULL, NULL, 1, 0),
(288, 'Victory_GOD', 'vijeshm331@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$RHcwOWpYYUtzZ2dVRERleA$xkZzBXMPaKphRkuNrownljsTEhlfgev1XLtKUxpR2M4', 'M Vijesh', '9342612052', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-02-12 05:16:03', '2026-02-12 05:17:26', 'active', '2026-02-12 05:17:26', 0, NULL, NULL, 1, 0),
(289, 'SSMD', 'diagne10saliou@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$YlZhMnR6TGVyRmVVWlBEUQ$wHZPxiLeGv3olnm+EcpplY7m4V8498sGqYH24hRpOaI', 'Serigne Saliou Mbacké Diagne', '+221776628039', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-02-12 12:58:33', '2026-02-12 13:35:12', 'active', '2026-02-12 13:35:12', 0, NULL, NULL, 1, 0),
(290, 'jonty_maurya', 'jontymaurya2004@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$R0tFMnF5dUxHL3g4SDFjRA$GPZIA6rOuvWOPpUx3/I4szUbQ8IHEk1n+/qDAzQozbg', 'JONTY MAURYA', '7903656286', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-02-13 14:39:42', '2026-02-13 16:08:25', 'active', '2026-02-13 16:08:25', 0, NULL, NULL, 1, 0),
(291, 'Matthew9516', 'dmatthewjeff27@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$U3RLZk5XUUFPU3ZvcE04TA$Kq+y4Pk4hRaz0UyFPp1LNsK7PqKNG7dAEHCC7SoFIfk', 'D MATTHEW JEFF', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-02-13 15:57:45', '2026-02-13 16:00:00', 'active', '2026-02-13 16:00:00', 0, NULL, NULL, 1, 0),
(292, 'IshaqAfkar', 'ishaqafkar123@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$MUt5b3RCcVNxaVBMUnVKOQ$1+aKznEMRJ3R9CvafvEs4bvLcIP3RDOwpkylZUWIPx8', 'Ishaq Afkar', '+94777138258', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-02-14 06:01:49', '2026-02-14 06:02:28', 'active', '2026-02-14 06:02:28', 0, NULL, NULL, 1, 0),
(293, 'dineshsinghdhami', 'dineshdhamidn@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$Q00xZVp6WHE5ZXdIWEJpdA$ayv4CIVGINxBnRbjBQAcdTrKWNGJlvMKbINJRX+/Zhw', 'Dinesh Singh Dhami', '', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-02-17 01:33:23', '2026-02-17 01:34:19', 'active', '2026-02-17 01:34:19', 0, NULL, NULL, 1, 0),
(294, 'wondmeneh', 'wnwondmeneh@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$TFVTZkEva3paMEFOejhHaA$ST5aknMA6iBW1/TMlUVzfx1Dm4vl7iW9/8f3Lr0Ipug', 'Wondmeneh Worku', '+251920726307', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-02-17 07:13:35', '2026-02-17 07:18:29', 'active', '2026-02-17 07:18:29', 0, NULL, NULL, 1, 0),
(295, 'umerfarooqazhar', 'umerfarooqazhar@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$elJQcmNTaERzb2xsOHMxRg$aph7mBvhTQg44+Jf7hHQmGfzkmRwud+aihdYcdNpjeA', 'Umer Farooq', '+923001216441', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-02-17 08:10:40', '2026-02-21 17:43:13', 'active', '2026-02-21 17:43:13', 0, NULL, NULL, 1, 0),
(296, 'Maestro', 'daoukris@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$aGdvMERMdnd1ZE8zdlU0cg$XC8/8XrwhO4tlxWwu5tVhaQQBbjE/Ic1xcOM8HNexGY', 'IKEFOUE LAMINE', '+22871783268', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-02-17 23:03:40', '2026-02-23 23:42:08', 'active', '2026-02-23 23:42:08', 0, NULL, NULL, 1, 0),
(297, 'V4L7R1E', 'erikawirth999@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$T2Y5QmNDVmhhL3RXb1NqUQ$uetHIkAteWIYMGdjS9WtE2IbCJ/eZxqTA1N075RCb/c', 'Erika Wirth', '+36202867965', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-02-18 13:44:06', '2026-02-18 13:46:04', 'active', '2026-02-18 13:46:04', 0, NULL, NULL, 1, 0),
(298, 'mujtaba', 'mujtaba1269@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$c1hkeDVXcnFkOEJlSlU1OQ$GEJW5HS005SR2kH+NdooF3o7HIS0QNUJ1+iDdw47a4U', 'syed mujtaba ahmed', '+919063152840', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-02-19 11:12:35', '2026-02-19 11:13:04', 'active', '2026-02-19 11:13:04', 0, NULL, NULL, 1, 0),
(299, 'BoseM', 'bosegmpulubusi@yahoo.com', '$argon2id$v=19$m=65536,t=4,p=3$cGtFeWNjc3hrOVVKaDZGMA$qRkap3Nhb9rZUxD7wR6tewZRf+0F+4kKwEXXIlUxK8A', 'Bose Gobitsa Mpulubusi', 'BoseM', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-02-19 14:01:04', '2026-02-24 18:15:22', 'active', '2026-02-24 18:15:22', 0, NULL, NULL, 1, 0),
(300, 'Babafils', 'amara.babadabala@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$TWJLWHVTQ3ZILkJmeU5SeQ$k+tOSrq8O7wDu5qDn/qjG7RQMq4AGNie1QaEaXUSeeY', 'Amara Baba Dabala', '+23566256865', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-02-20 00:57:21', '2026-02-20 00:58:04', 'active', '2026-02-20 00:58:04', 0, NULL, NULL, 1, 0),
(301, 'Megansnyder4', 'megan.snyder4@snhu.edu', '$argon2id$v=19$m=65536,t=4,p=3$ZWxZU2pNTFNUNWtPaWpPaA$L5vQ4WrRY+UtG82l8TPUmoCUGIjp5422bWoR6SIpRR0', 'Megan Snyder', '2343876587', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-02-21 23:00:05', '2026-02-21 23:03:19', 'active', '2026-02-21 23:03:19', 0, NULL, NULL, 1, 0),
(302, 'udaysiddapur', 'udaysiddapur@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$Q29ZWUlMY0dVTGQzN2FqdA$nZWDoJsfBmToF7ch+2hOrC/MIYE78wpZHrYAKFUKAh4', 'Uday', '0064212149734', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-02-23 20:57:59', '2026-02-23 21:00:04', 'active', '2026-02-23 21:00:04', 0, NULL, NULL, 1, 0),
(303, 'PRAKASH092', 'mreddyprakash092@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$S0ZQL0R6OEdKem9wWjJ2OQ$8m4u3Emlel9X0T84wu3OM9IcnGdQPCy4y17i82wgYM4', 'Mallela Reddy Prakash', '+918019740724', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-02-26 12:44:20', '2026-02-26 12:49:10', 'active', '2026-02-26 12:49:10', 0, NULL, NULL, 1, 0),
(304, 'Gowtham', 'gavireddigowtham91962@gmail.com', '$argon2id$v=19$m=65536,t=4,p=3$WHNpSDh1b2ZkVG9FdGc3bQ$83xKcheOre/57C5EyBJanohpB+dVmGGSklz6W8KHfAY', 'Gavireddy Gowtham Kumar', '9640336058', NULL, 'user', 1, NULL, NULL, NULL, NULL, '2026-03-02 10:14:07', '2026-03-02 10:14:34', 'active', '2026-03-02 10:14:34', 0, NULL, NULL, 1, 0);

--
-- Triggers `users`
--
DELIMITER $$
CREATE TRIGGER `after_user_login` AFTER UPDATE ON `users` FOR EACH ROW BEGIN
  IF NEW.failed_attempts = 0 AND OLD.failed_attempts > 0 THEN
    -- User successfully logged in (failed attempts reset)
    -- The application will handle session creation
    DO 0;
  END IF;
END
$$
DELIMITER ;
DELIMITER $$
CREATE TRIGGER `update_last_login` AFTER UPDATE ON `users` FOR EACH ROW BEGIN
    IF NEW.login_attempts = 0 AND OLD.login_attempts > 0 THEN
        UPDATE users SET last_login = NOW() WHERE id = NEW.id;
    END IF;
END
$$
DELIMITER ;

-- --------------------------------------------------------

--
-- Table structure for table `user_completed_lessons`
--

CREATE TABLE `user_completed_lessons` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `content_id` int(11) NOT NULL,
  `package_id` int(11) NOT NULL,
  `completion_token` varchar(64) NOT NULL,
  `completed_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `ip_address` varchar(45) DEFAULT NULL,
  `user_agent` text DEFAULT NULL,
  `is_verified` tinyint(1) NOT NULL DEFAULT 0,
  `verified_at` timestamp NULL DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `user_completed_lessons`
--

INSERT INTO `user_completed_lessons` (`id`, `user_id`, `content_id`, `package_id`, `completion_token`, `completed_at`, `ip_address`, `user_agent`, `is_verified`, `verified_at`) VALUES
(5, 27, 62, 2, 'a675ae5b83034e8d457e348288e419d02639b3c1f10d88cae6a49b0d301cfdc9', '2025-12-09 10:09:35', '157.49.165.10', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 1, NULL),
(6, 27, 61, 2, 'dd0a282a425a707f1e6991dbe7d964dc385ed3b335f049fe02897e95288b3282', '2025-12-09 10:14:39', '157.49.165.10', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 1, NULL),
(7, 27, 35, 2, '08f49f7f4b55190e0e95f60a0ef4f9f467a95c4a1fc1449c8b993c4147277ab5', '2025-12-09 10:21:03', '157.49.165.10', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 1, NULL),
(8, 27, 63, 2, 'b45fa2015a624f8d6e4a981b008ba96648cb3996d5a5e81b4a0c44a36d6e0988', '2025-12-09 10:25:18', '157.49.165.10', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 1, NULL),
(9, 27, 64, 2, 'a428a4c5c08d985642a4d92d87f5c4182234e87dd6b51611ad9dbab6ecdba24e', '2025-12-09 10:28:40', '157.49.165.10', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 1, NULL),
(10, 27, 65, 2, 'a4262a1e3221c212862a236ede22945f5cf3769474d6222006a25bdea1edff12', '2025-12-09 10:29:57', '157.49.165.10', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 1, NULL),
(11, 27, 66, 2, 'a46936e470c0743a7ef4530f60b99066c910ecc6f8160e8ca9472011f0e0d338', '2025-12-09 10:38:22', '157.49.165.10', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 1, NULL),
(12, 27, 67, 2, 'ec3537088b7358fc5969adef0555235abf3cebb981dd096afffcacb0b38590d3', '2025-12-09 10:39:27', '157.49.165.10', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 1, NULL),
(13, 21, 66, 2, '317b23bea4517ae4da0349f8c0446d8681e83bc35dbb16f8dc3bd0d3c549cd82', '2025-12-09 11:09:41', '157.49.165.10', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:145.0) Gecko/20100101 Firefox/145.0', 1, NULL),
(14, 21, 65, 2, 'f99dc6bdc8039677d6124f1af998a428eb9fcc1f8b48e63da086bb40820303de', '2025-12-09 11:27:54', '157.49.165.10', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:145.0) Gecko/20100101 Firefox/145.0', 1, NULL),
(15, 21, 67, 2, '1be99b09fd48ea915be13c32eff62c30e3bf51bdadf6e89e21c1d90b77179f41', '2025-12-09 11:34:48', '152.59.93.201', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:145.0) Gecko/20100101 Firefox/145.0', 1, NULL),
(16, 27, 68, 2, 'c1f7ad22771acd5bea6befc6bd04e09abe335ff4375a23510260b1d1c879be60', '2025-12-09 11:36:14', '152.59.93.201', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 1, NULL),
(17, 27, 69, 2, 'ea7a04fb0e557d88927599c23dd38745e195e263f4fb4a353f6dd17a61db1b04', '2025-12-09 11:36:19', '152.59.93.201', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 1, NULL),
(18, 27, 70, 2, '7e048541d47f5968ecc3af19430aaf3cc343fd08b1c1403f856be4786bac2001', '2025-12-10 05:59:04', '152.59.93.97', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 1, NULL),
(19, 27, 72, 2, '70f2a3ad77c11ab0b5958a83cfce1339a3f8647c1967f1f660195e53dd248f92', '2025-12-10 06:38:57', '2409:40d6:30:9e5c:5519:a02c:7658:9d68', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36', 1, NULL),
(20, 27, 73, 2, '3cd2be98f4dfe1d86075b878393dde8dd716e873f6131ba488be924ace810bb1', '2025-12-10 07:10:00', '152.59.93.97', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 1, NULL),
(21, 27, 74, 2, 'ef9bb8b6d56e02ededc632b1bfdf026819b5b5f9d32c7512dfa3e0dacd6938e9', '2025-12-10 08:11:42', '152.59.93.97', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 1, NULL),
(22, 27, 75, 2, '7a6ba6660881058504d6d73b8809098641906bb696b170104e67698989b9d95e', '2025-12-10 08:13:01', '152.59.93.97', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 1, NULL),
(23, 27, 76, 2, '28af560661ab47816cdf04a1f4b6e2919daf1fa03aa27c51f1657f557b41f867', '2025-12-10 08:13:54', '152.59.93.97', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 1, NULL),
(24, 27, 77, 2, '050d48d9e14d2215acee7a64cca941984e0822a8cbf60919917470f362cb2a0c', '2025-12-10 08:15:30', '152.59.93.97', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 1, NULL),
(25, 21, 81, 2, '7d888c52a8f5d270a53bd27f721cb8737c1bdf8359774975b1b094490bf78215', '2025-12-12 05:33:06', '2409:40e3:17b:f924:3419:dfaf:d066:accb', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36', 1, NULL),
(26, 21, 82, 2, '00c33428b3e3953f5d06c702805779130abda71abf7b24a885cec70f67861607', '2025-12-12 05:33:32', '2409:40e3:17b:f924:3419:dfaf:d066:accb', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36', 1, NULL),
(27, 21, 83, 2, '71c2660f6d354f8a7b2bcf01069bf71b3917136f4ca2117078aa73f79af70ce0', '2025-12-12 05:33:41', '2409:40e3:17b:f924:3419:dfaf:d066:accb', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36', 1, NULL),
(28, 27, 81, 2, 'd64adbceb3d0d5ce82151d260b339f9004dc3b20aabf7170a797b76b7500d550', '2025-12-12 05:39:43', '152.59.93.22', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 1, NULL),
(29, 27, 82, 2, '7373d8940d5b65caa852a4a8c4283a1bf81d1730c8a675c2dfc70e60012a687e', '2025-12-12 05:40:24', '152.59.93.22', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 1, NULL),
(30, 27, 83, 2, '5b642dbef8f4cac3acdde60b35ebbcbbca24c54e412c846fa6ff396bc3b994ad', '2025-12-13 04:29:48', '157.49.146.159', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 1, NULL),
(31, 27, 84, 2, 'bc7041abc6115e50a6e717af730475dfce28c392fbc6fda18ed166c3dee63b1d', '2025-12-13 04:57:36', '157.49.146.159', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 1, NULL),
(32, 27, 85, 2, '46010b5748743d93dd4aab350793ea9e87acfde1ef465608cd13f4054f2da747', '2025-12-13 05:20:24', '157.49.146.159', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 1, NULL),
(33, 27, 86, 2, 'b71ba4fb6bc9cf5fc0f9ce85fe980068fc3b590e4b632d2c9c5c685f5271d024', '2025-12-13 05:20:31', '157.49.146.159', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 1, NULL),
(34, 27, 87, 2, '4063a4fb53f1beeccae256cc9c59433859978a883a63454bb83fcaefc5c262c6', '2025-12-13 06:09:44', '157.49.146.159', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 1, NULL),
(35, 27, 88, 2, 'c5dc7fe2fdcf6582e0d4ed0ec4a8cd34340e2a95dbcaec3716bd6163848a45dc', '2025-12-13 06:23:46', '157.49.146.159', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36', 1, NULL),
(36, 27, 89, 2, '0a78f39263447995d94788ddfb90efb514bba457178d4b485867bea80be5252d', '2025-12-13 06:27:12', '157.49.146.159', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36', 1, NULL),
(37, 27, 90, 2, '5c60f769c840c3aea5d8462b82b7a6228e5e793aa78b5e8de682729665e05d94', '2025-12-13 06:27:23', '157.49.146.159', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36', 1, NULL),
(38, 27, 91, 2, '0df1905069e20d554bc41f0dde537b1e9ed9d74ad5e5ddb1d1f26905dbad037a', '2025-12-13 06:30:04', '157.49.146.159', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36', 1, NULL),
(39, 27, 92, 2, '32cc5dd87fe29e5bd8bb2428b425d3e89dcd8b7e0ab488c27006c59aa2fc04f9', '2025-12-13 06:30:15', '157.49.146.159', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36', 1, NULL),
(40, 27, 96, 2, '838297d197b5afaf3b1bf2c46e31445b4f55cf90d963da4529a7be56f5d12372', '2025-12-13 07:03:12', '157.49.146.159', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36', 1, NULL),
(41, 27, 94, 2, 'c82850e99ff9f661e179cf5e56df3b605107ec232662a54de7f079d4d5bfa6f5', '2025-12-13 07:09:09', '157.49.146.159', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36', 1, NULL),
(42, 27, 95, 2, '97eefaa51be8628b57273d535c2c1dd8c861955277d998c43737dfa82cb8e433', '2025-12-13 07:10:42', '157.49.146.159', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36', 1, NULL),
(43, 27, 99, 2, 'c5d5d0ec74b07e64102720a124364d721d9ceab952d51465f6cc41dd41cbe8a2', '2025-12-13 07:19:38', '157.49.146.159', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36', 1, NULL),
(44, 27, 97, 2, 'e636a3d6cfd703f1c7fb818d651ee2a6356723799f25bd2c2becd198870bb3f1', '2025-12-13 07:33:34', '2409:40d6:1197:279b:d0b5:2ffd:462c:6a4d', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36', 1, NULL),
(45, 27, 98, 2, '0d5affcf6d32d38ae463f54cb3b61cd786a94c34391d0b100543a40a00542c32', '2025-12-13 07:38:18', '2409:40d6:1197:279b:d0b5:2ffd:462c:6a4d', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36', 1, NULL),
(46, 27, 121, 2, '9f23b9043ee3b9a021009db2dbffd3abd443a0851dda22f89aa2fecd2ab4f733', '2025-12-17 10:43:13', '152.58.103.24', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36', 1, NULL),
(47, 27, 124, 2, '3b41d45471be44520a2baf7c3380bd6ab601d1bc846659cf104a2ff6e17a07f8', '2025-12-17 10:51:09', '152.58.103.24', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36', 1, NULL),
(48, 27, 126, 2, '80c14af960c8822b894f45b2eacb98591573154b3fa0c2967e2d641e655b98b4', '2025-12-17 11:15:54', '152.58.103.24', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36', 1, NULL),
(49, 27, 102, 1, '79e5a23430f2365a5aba55f00104351a0682811c049c084e86e80ccb91dac315', '2025-12-18 09:10:55', '152.58.103.61', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36', 1, NULL),
(50, 27, 103, 1, 'd62ba400da993129484cb7a37dc434f9d4cbfcd6d0e488ebad3f95623ba113ef', '2025-12-18 09:11:07', '152.58.103.61', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36', 1, NULL),
(51, 27, 104, 1, '18f21bb9abc22881ea610d15a2629f900fb9d41104a6136548a3b743715992a3', '2025-12-18 09:11:15', '152.58.103.61', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36', 1, NULL),
(52, 27, 100, 1, 'c84fafcf6252ab4a07292f1d4fafac6c460dbdce3408d34e44d599eea851f4ff', '2025-12-18 09:11:22', '152.58.103.61', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36', 1, NULL),
(53, 27, 129, 1, '0566852f59737cb8e33bdf016db8136d3fc65034837806c0931f62b6f2c4537d', '2025-12-19 04:33:30', '152.58.74.55', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36', 1, NULL),
(54, 27, 144, 1, 'c9a1c844a92e321fe4237bcc30de448b751a7178670f97b57cec670bdcdf720b', '2025-12-19 05:55:30', '152.58.74.55', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36', 1, NULL),
(55, 27, 134, 1, '1308874d90c7604c20a2ec22afe14d3642ecefd27716668e743cbd2086f799e2', '2025-12-19 06:05:00', '152.58.74.55', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36', 1, NULL),
(56, 27, 137, 1, '3ed090fd7a821c61743527440772ba8d61ba240e2fb82e5f46ed3246553e4a53', '2025-12-19 06:16:09', '152.58.74.55', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36', 1, NULL),
(57, 27, 138, 1, 'ccb8975808d32d7d96ab24351fd0189bde08b389a5290f16d24b8b2ce06ee098', '2025-12-20 03:55:28', '152.59.93.186', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36', 1, NULL),
(58, 141, 176, 1, '7e2c39f2620475571338c0f2117ef5fb57b8116796bbb06c9abf7303a0fd8508', '2025-12-20 12:41:07', '77.222.234.9', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36', 1, NULL),
(59, 27, 143, 1, 'c232d204705479946d4075394ef1dcdaa4857fd065d0c028d096c04ca1ba17b0', '2025-12-22 08:17:11', '157.49.175.169', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36', 1, NULL),
(60, 27, 145, 1, '187ef226155fc1d863d772dc2f5851e7fb07c6e211bf7c40b68defcae4147544', '2025-12-22 08:17:33', '157.49.175.169', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36', 1, NULL),
(61, 27, 149, 1, '06d1ffee961bfb2616eeec026328dc52ff5923749c7bbc8e7074328799de7a09', '2025-12-22 08:23:01', '157.49.175.169', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36', 1, NULL),
(62, 27, 132, 1, '495c0cf66410e207fff2694e978bee8ab1293ed7e5a5a827afb0e3c3adcf1867', '2025-12-23 10:00:58', '47.15.21.142', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36', 1, NULL),
(63, 129, 132, 1, 'acff4c424a5a4932105574977d2dadecd563789da16e098a62dc9b0721ce280c', '2025-12-26 12:15:12', '2401:4900:7074:badf:d9a2:7dec:b4c2:1f03', 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36 OPR/93.0.0.0', 1, NULL),
(64, 27, 169, 1, '451e6198701e48d759a2f0571816ef21f17370a23662502551e10dc7d3b9b34d', '2025-12-30 08:04:49', '2409:40d6:1192:64d9:e8be:88b1:3e5e:fd25', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36', 1, NULL),
(65, 209, 176, 1, 'e8a3bf805b86af68e3c1914af2c96caa45082908cdfbadaf1d89f9775fad6a9e', '2026-01-14 05:43:53', '2409:40c2:1160:285f:74ef:c1be:7411:80', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36', 1, NULL),
(66, 209, 130, 1, 'cb2e086e4d0308cc003d1aa2611ebae55cd8d87187f9a9568b0fbfd20ba60ef3', '2026-01-14 05:45:07', '2409:40c2:1160:285f:74ef:c1be:7411:80', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36', 1, NULL),
(67, 209, 129, 1, '3ff815ac1767ad659a7a5a17e91cccf04a24f1f8bfaf3a258600d35f55f80ac5', '2026-01-14 05:47:40', '2409:40c2:1160:285f:74ef:c1be:7411:80', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36', 1, NULL),
(68, 109, 129, 1, 'c10b8a44dd9e74282cd789aa09115cb94711a1236bbfb000de5abdc404dfdbeb', '2026-01-20 05:14:22', '103.178.143.212', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36', 1, NULL),
(69, 230, 129, 1, '5c97bd1c872e3f43520bb6c675f0146c9d30e963106f08ee4ceacc75b5e64ed5', '2026-01-20 10:17:28', '2401:4900:1c2d:54b9:f416:453c:5abf:d92d', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 1, NULL),
(70, 230, 130, 1, 'eee4bca96c46713f4092c3d919fedeb138236731c46237e3a5b3fb5d9fda2287', '2026-01-20 10:20:50', '2401:4900:1c2d:54b9:f416:453c:5abf:d92d', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 1, NULL),
(71, 230, 176, 1, '1c891a554d58ba5c82fbfc48f20f2425d30973448ad725cd2da93e2755f3c0bf', '2026-01-20 10:29:43', '2401:4900:1c2d:54b9:f416:453c:5abf:d92d', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 1, NULL),
(72, 230, 132, 1, '303ee8e1fcf6249741e89cacf55beb75292bdb08cdbe35f47c4cc1bbc4edf8a3', '2026-01-20 10:32:30', '2401:4900:1c2d:54b9:f416:453c:5abf:d92d', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 1, NULL),
(73, 230, 131, 1, '5a614cc51f389b36cf9de46e9a52b1b50f54af72db83e0a777e26e821752a737', '2026-01-20 10:34:52', '2401:4900:1c2d:54b9:f416:453c:5abf:d92d', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 1, NULL),
(74, 230, 178, 1, '3d363adc7014169aedd1b95199d149423a73a000ec23ae00ab030ac6ae24092d', '2026-01-20 10:46:53', '2401:4900:1c2d:54b9:f416:453c:5abf:d92d', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 1, NULL),
(75, 230, 134, 1, 'd3fce113093417e20684d3d3c3f2002a7b19bc4107ff49b32add0e73fb5e5d18', '2026-01-20 10:56:57', '2401:4900:1c2d:54b9:f416:453c:5abf:d92d', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 1, NULL),
(76, 230, 135, 1, '6003d914a1d6b68762ffe2b2e92323030050059dd8eb8a5c11d06d1a2982862c', '2026-01-20 11:08:54', '2401:4900:1c2d:54b9:f416:453c:5abf:d92d', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 1, NULL),
(77, 230, 133, 1, '28049493d20baa1379a43c1c4a568fda70f88fbe2b554dc31d80755325ce5359', '2026-01-20 11:27:22', '2401:4900:1c2d:54b9:f416:453c:5abf:d92d', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 1, NULL),
(78, 230, 177, 1, '9b762049a46d6dd4b32f96f9ff2829d0cb1ca3bc402c7e0de1a3e1b572ad7b15', '2026-01-23 10:56:00', '2401:4900:1c9a:3bdb:6c1b:7d75:db29:dca1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 1, NULL),
(79, 230, 136, 1, '8cb52bacb92393ba84781e4fe4854d38519546b6db543d7fa11a31949faf7137', '2026-01-23 11:04:29', '2401:4900:1c9a:3bdb:6c1b:7d75:db29:dca1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 1, NULL),
(80, 230, 137, 1, 'fd26039fcaa572204eb271979b2237b0fbdd29cff6b083782e8c6734228774d1', '2026-01-23 11:14:18', '2401:4900:1c9a:3bdb:6c1b:7d75:db29:dca1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 1, NULL),
(81, 230, 138, 1, '250fc11f9a6ad45962b6f8aeead27f87470ef961c2238bb6a826805d52a7c86e', '2026-01-23 11:16:05', '2401:4900:1c9a:3bdb:6c1b:7d75:db29:dca1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 1, NULL),
(82, 230, 153, 1, '0895fb1eab166dfe651c5af54e143f60a86ad6836432997b651261faeae0825d', '2026-01-23 11:24:27', '2401:4900:1c9a:3bdb:6c1b:7d75:db29:dca1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 1, NULL),
(83, 241, 129, 1, 'e45fcf70b490232233f37c0fe08e45f5f212d75d99dafe7c670dc022d5dda78a', '2026-01-23 18:44:10', '2401:4900:8898:bcd7:e843:105b:4e:a89', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36', 1, NULL),
(84, 230, 154, 1, '33d80f3d3cad5d2b4013ec5849156feb032f42f87934f69581979e27edab32fb', '2026-01-28 10:41:50', '2401:4900:1c2d:faba:1d72:7af6:380c:7c50', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 1, NULL),
(85, 230, 155, 1, 'a2e6232bb9d37ea55da493b8cb5fac0cbffa339b3a9b362a9f4a6d8b57d04cac', '2026-01-28 10:54:20', '2401:4900:1c2d:faba:1d72:7af6:380c:7c50', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 1, NULL),
(86, 230, 156, 1, 'e43121c34219e218e77dfcc251492d56007c9496a183ba436e16d857b87e76c0', '2026-01-28 11:00:46', '2401:4900:1c2d:faba:1d72:7af6:380c:7c50', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 1, NULL),
(87, 230, 157, 1, 'ae05c41d379b28e6423653617c315acb25cda3046a1cf6a07edadd0fb239a5ac', '2026-01-28 11:11:20', '2401:4900:1c2d:faba:1d72:7af6:380c:7c50', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 1, NULL),
(88, 241, 130, 1, 'a5efd4444d8706eb277779513ef68cedc338301a7af2d957b1139569d02701e0', '2026-01-30 05:04:59', '2401:4900:1c80:55da:f914:4c5c:66e:e6d5', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36', 1, NULL),
(89, 241, 176, 1, '1436d841bbe8270a35332b04841a82cbbf39e26620a067a1eec20947d61040cf', '2026-01-30 05:07:05', '2401:4900:1c80:55da:f914:4c5c:66e:e6d5', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36', 1, NULL),
(90, 241, 132, 1, '665c004abaf9cc7781374117fcfd2da228cae30fba124926ae9944e21bd0df82', '2026-01-30 09:14:55', '2401:4900:1c80:55da:ccee:669b:108c:1c08', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36', 1, NULL),
(91, 241, 131, 1, 'e2058cd095a91a7e74f300f5d582b4fb98cb2f8cfc1c5f3cede48359719b5150', '2026-01-30 09:17:45', '2401:4900:1c80:55da:ccee:669b:108c:1c08', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36', 1, NULL),
(92, 241, 178, 1, '9e783ca2e0e5af1ff76ce841958910795e5ffe092dd46c9c1fde723278823771', '2026-01-30 09:20:49', '2401:4900:1c80:55da:ccee:669b:108c:1c08', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36', 1, NULL),
(93, 241, 134, 1, '31a1bfae07d46ddd276d08f7b29d31056e19851c6a9cfc1d392386c7718abc06', '2026-01-30 09:30:04', '2401:4900:1c80:55da:ccee:669b:108c:1c08', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36', 1, NULL),
(94, 241, 135, 1, '0359989a145975cd2baa61521ac73582b264de9414e4fa55bf7aa3e3877b88de', '2026-01-30 09:33:25', '2401:4900:1c80:55da:ccee:669b:108c:1c08', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36', 1, NULL),
(95, 241, 133, 1, '1c3f150986f168013b47be96fd3f5277c5c8b7efb9fae6b25a104506995c057f', '2026-01-30 09:37:54', '2401:4900:1c80:55da:ccee:669b:108c:1c08', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36', 1, NULL),
(96, 241, 177, 1, '3b84c42c61b81138d6049be0a67933a8d0d62891e54bff9e7bdb5ab746570374', '2026-01-30 09:40:13', '2401:4900:1c80:55da:ccee:669b:108c:1c08', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36', 1, NULL),
(97, 241, 191, 1, '0b7f82fe304a3d41f105100924b9e170c96b9c14b62327ae58ce72f5b2781863', '2026-01-30 09:42:54', '2401:4900:1c80:55da:ccee:669b:108c:1c08', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36', 1, NULL),
(98, 230, 158, 1, '1678dee4e12bf803287aa42bfac348918be83f0ca3937390836c0c68bf374bbd', '2026-01-30 09:43:36', '2401:4900:1c9a:da92:8dde:378f:a835:300d', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 1, NULL),
(99, 230, 159, 1, '532adff0b88b0617d36155d2839a7ccd6b3c711199680611aa052514a2033c7a', '2026-01-30 09:46:58', '2401:4900:1c9a:da92:8dde:378f:a835:300d', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 1, NULL),
(100, 230, 160, 1, '0a8892cf0180244c471a15f559905c12cd76a81f109904ce1428479087ef4bca', '2026-01-30 09:52:33', '2401:4900:1c9a:da92:8dde:378f:a835:300d', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 1, NULL),
(101, 230, 161, 1, '7f3683d9a6d846dcd2595cc533e9db2d35615fb0076872448183693ea05716c2', '2026-01-30 09:57:13', '2401:4900:1c9a:da92:8dde:378f:a835:300d', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 1, NULL),
(102, 230, 191, 1, '87df7d13537df087de7380a6ed797eda40566c06796b4aa9e23d7ee5ee9860fe', '2026-01-30 09:57:40', '2401:4900:1c9a:da92:8dde:378f:a835:300d', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 1, NULL),
(103, 230, 190, 1, 'fee70c26f319a8058335ca60fbcc73eca0d9149eb7ea7205510099721399ceab', '2026-01-30 09:57:45', '2401:4900:1c9a:da92:8dde:378f:a835:300d', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 1, NULL),
(104, 241, 137, 1, '5e78faa07212da6f200b776c97353f6bf6bd4b84d251d259b320a1877fc96c19', '2026-01-30 10:04:58', '2401:4900:1c80:55da:ccee:669b:108c:1c08', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36', 1, NULL),
(105, 230, 162, 1, '1ada890148c1f975ad4312d51b9282b5f25a544a07c91042231ea801d631937c', '2026-01-30 10:10:01', '2401:4900:1c9a:da92:8dde:378f:a835:300d', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 1, NULL),
(106, 241, 138, 1, '3dd27f9616043f84411737bd5923389f40ee8f6680429a17c7fd3ff572540944', '2026-01-30 10:13:05', '2401:4900:1c80:55da:ccee:669b:108c:1c08', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36', 1, NULL),
(107, 230, 163, 1, 'ac76d9e36f9b7695d9670a19704c482295119d7e21d07612479e643010656161', '2026-01-30 10:15:28', '2401:4900:1c9a:da92:8dde:378f:a835:300d', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 1, NULL),
(108, 230, 165, 1, '5a714b88f2228f23da07e13aeb79aed5c193eb9126a793977f976fb96e897e45', '2026-01-30 10:20:49', '2401:4900:1c9a:da92:8dde:378f:a835:300d', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 1, NULL),
(109, 230, 166, 1, '3470688befce2f7c94ed8758816a41f27d6b1550907d7f74e5914d1fce427540', '2026-01-30 10:23:06', '2401:4900:1c9a:da92:8dde:378f:a835:300d', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 1, NULL),
(110, 241, 190, 1, '16a8900adfe7c87764db164211fc5f116050073a45786a209f58bbad56ab34e8', '2026-01-30 10:24:14', '2401:4900:1c80:55da:ccee:669b:108c:1c08', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36', 1, NULL),
(111, 230, 167, 1, '667f1fb742bca1483985902cee076b4d09c9cdfae0f11fadc54671a910c1146e', '2026-01-30 10:27:39', '2401:4900:1c9a:da92:8dde:378f:a835:300d', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 1, NULL),
(112, 241, 153, 1, 'e76682a8fd1499af15324396342e1725b75751679826a74a9968161dbc38d09f', '2026-01-30 11:37:07', '2401:4900:1c80:55da:5197:782a:af94:baaf', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36', 1, NULL),
(113, 230, 181, 1, '550cbc01147673f76e56814a73997c8069172d57dbe9300b622cb3281dedfae3', '2026-02-02 06:08:11', '2401:4900:1c8e:cdd4:491b:66cd:9189:5a1f', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36', 1, NULL),
(114, 230, 182, 1, '81373caf2f2b20061018490ca8b5a630f5e81d9bab5c60e1645cc2dc74af8738', '2026-02-02 06:15:10', '2401:4900:1c8e:cdd4:491b:66cd:9189:5a1f', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36', 1, NULL),
(115, 230, 183, 1, 'ab677985fa4725e7646f97be4c0ac9bd5f59ad0e8912d65a53e0f00f0edb4db3', '2026-02-02 06:17:16', '2401:4900:1c8e:cdd4:491b:66cd:9189:5a1f', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36', 1, NULL),
(116, 230, 184, 1, 'b6f00558bf85bdbf8ffcd913bc7d02d00c48043f8d7cd8d19144cf62194c3d8a', '2026-02-02 06:19:50', '2401:4900:1c8e:cdd4:491b:66cd:9189:5a1f', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36', 1, NULL),
(117, 230, 187, 1, 'ee2d25d8cf6b980e0bfe2a9f71f9dbad661df2c32243835f6296dfcf5705cdaa', '2026-02-02 06:25:07', '2401:4900:1c8e:cdd4:491b:66cd:9189:5a1f', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36', 1, NULL),
(118, 230, 139, 1, '9c89a77d66d0db08df5adb50e34090a90421c1d149841093e7e28fa447231cef', '2026-02-02 06:29:59', '2401:4900:1c8e:cdd4:491b:66cd:9189:5a1f', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36', 1, NULL),
(119, 230, 140, 1, 'f4b5346517d684e4ccbac631ac1289060c16d40c29590e30f25e321a2631e803', '2026-02-02 06:35:37', '2401:4900:1c8e:cdd4:491b:66cd:9189:5a1f', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36', 1, NULL),
(120, 230, 141, 1, '11635bb048e40da70de4751ce7e383b569d09aacb1272cd756b8d41895b5586a', '2026-02-02 06:40:26', '2401:4900:1c8e:cdd4:491b:66cd:9189:5a1f', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36', 1, NULL),
(121, 230, 142, 1, 'eb37a513a32720edae10e43842f83746c9c8271d27ff2b43b9e74a74cc2a3810', '2026-02-02 06:43:34', '2401:4900:1c8e:cdd4:491b:66cd:9189:5a1f', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36', 1, NULL),
(122, 230, 171, 1, '5f51aa1d7ea4def0a2436484b463aede502866570fd98cb492fa7793a07639d2', '2026-02-02 10:55:14', '2401:4900:1c8e:cdd4:1cfb:20b5:3311:a3a8', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36', 1, NULL),
(123, 230, 172, 1, '4b170bcf90fd6c9cea6cc9a5968ddf2d5c5f87e72625aab67ec4db340cb4051a', '2026-02-02 10:59:37', '2401:4900:1c8e:cdd4:1cfb:20b5:3311:a3a8', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36', 1, NULL),
(124, 205, 129, 1, 'e3a38ee82ee80afbfc59b3167b53502803cd0a686ab2f32bb2a783cf56c64b74', '2026-02-04 12:57:40', '81.17.122.101', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36', 1, NULL),
(125, 205, 191, 1, '594a345d499b259701084ae8c9d5216e94219c4bc5914b0f8911e4adbf4dc526', '2026-02-08 14:56:55', '217.216.103.45', 'Mozilla/5.0 (Android 15; Mobile; rv:147.0) Gecko/147.0 Firefox/147.0', 1, NULL),
(126, 205, 195, 1, '295a15fcb291d76f18a589fb6ca853d0f7b3df408915c332851ab047d7936cf4', '2026-02-08 14:59:17', '217.216.103.45', 'Mozilla/5.0 (Android 15; Mobile; rv:147.0) Gecko/147.0 Firefox/147.0', 1, NULL),
(127, 205, 196, 1, '731103d3a8af9304e65099f0906e2f3c847d2fc759bc27d373ea31d30d47e02c', '2026-02-08 15:02:42', '217.216.103.45', 'Mozilla/5.0 (Android 15; Mobile; rv:147.0) Gecko/147.0 Firefox/147.0', 1, NULL),
(128, 205, 190, 1, '798c07bd025c9b6965bf390e9f8c35113acb43e622cf584e9f28f07aafe2b4e2', '2026-02-08 15:03:18', '217.216.103.45', 'Mozilla/5.0 (Android 15; Mobile; rv:147.0) Gecko/147.0 Firefox/147.0', 1, NULL),
(129, 205, 163, 1, '6167c1800b069c670164f8b7e5da66dcb0a551784c1b75422bdbc2634b50735b', '2026-02-08 19:00:55', '217.216.103.45', 'Mozilla/5.0 (Android 15; Mobile; rv:147.0) Gecko/147.0 Firefox/147.0', 1, NULL),
(130, 205, 165, 1, 'd6f108c87619808dcac1d57f85b35eed998f0d4055f681eaf1a702bfc54e4bad', '2026-02-08 19:05:40', '217.216.103.45', 'Mozilla/5.0 (Android 15; Mobile; rv:147.0) Gecko/147.0 Firefox/147.0', 1, NULL);

-- --------------------------------------------------------

--
-- Table structure for table `user_lessons`
--

CREATE TABLE `user_lessons` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `lesson_id` int(11) NOT NULL,
  `completed_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `time_spent` int(11) DEFAULT 0,
  `progress` int(11) DEFAULT 100,
  `notes` text DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Triggers `user_lessons`
--
DELIMITER $$
CREATE TRIGGER `log_academy_lesson_completion` AFTER INSERT ON `user_lessons` FOR EACH ROW BEGIN
  INSERT INTO `activity_logs` (user_id, action, details, course_id, lesson_id)
  SELECT NEW.user_id, 'lesson_completed',
         CONCAT('Completed lesson: ', (SELECT title FROM course_lessons WHERE id = NEW.lesson_id)),
         cs.course_id, NEW.lesson_id
  FROM course_lessons l
  JOIN course_sections cs ON l.section_id = cs.id
  WHERE l.id = NEW.lesson_id;
END
$$
DELIMITER ;
DELIMITER $$
CREATE TRIGGER `log_lesson_completion` AFTER INSERT ON `user_lessons` FOR EACH ROW BEGIN
  INSERT INTO `activity_logs` (user_id, action, details, course_id, lesson_id)
  SELECT NEW.user_id, 'lesson_completed',
         CONCAT('Completed lesson: ', (SELECT title FROM course_lessons WHERE id = NEW.lesson_id)),
         cs.course_id, NEW.lesson_id
  FROM course_lessons l
  JOIN course_sections cs ON l.section_id = cs.id
  WHERE l.id = NEW.lesson_id;
END
$$
DELIMITER ;

-- --------------------------------------------------------

--
-- Table structure for table `user_purchases`
--

CREATE TABLE `user_purchases` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `package_id` int(11) NOT NULL,
  `transaction_id` varchar(100) DEFAULT NULL,
  `payment_method` varchar(50) DEFAULT NULL,
  `amount_paid` decimal(10,2) NOT NULL,
  `currency` varchar(3) DEFAULT 'USD',
  `payment_status` enum('pending','completed','failed','refunded','cancelled') DEFAULT 'pending',
  `payment_gateway_response` longtext DEFAULT NULL CHECK (json_valid(`payment_gateway_response`)),
  `purchase_date` timestamp NULL DEFAULT current_timestamp(),
  `expires_at` datetime DEFAULT NULL,
  `attempts_used` int(11) DEFAULT 0,
  `max_attempts` int(11) DEFAULT 3,
  `discount_code` varchar(50) DEFAULT NULL,
  `discount_amount` decimal(10,2) DEFAULT 0.00,
  `status` enum('active','expired','used','cancelled') DEFAULT 'active',
  `notes` text DEFAULT NULL,
  `purchase_amount` decimal(10,2) DEFAULT 0.00,
  `razorpay_order_id` varchar(100) DEFAULT NULL,
  `razorpay_payment_id` varchar(100) DEFAULT NULL,
  `razorpay_signature` varchar(255) DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `user_purchases`
--

INSERT INTO `user_purchases` (`id`, `user_id`, `package_id`, `transaction_id`, `payment_method`, `amount_paid`, `currency`, `payment_status`, `payment_gateway_response`, `purchase_date`, `expires_at`, `attempts_used`, `max_attempts`, `discount_code`, `discount_amount`, `status`, `notes`, `purchase_amount`, `razorpay_order_id`, `razorpay_payment_id`, `razorpay_signature`, `created_at`, `updated_at`) VALUES
(24, 13, 1, 'CWL_1757996390_13_1', 'razorpay', 0.00, 'USD', 'pending', NULL, '2025-09-16 04:19:50', NULL, 0, 3, NULL, 0.00, '', NULL, 0.02, 'order_RI8fWnZvj5BRxj', NULL, NULL, '2025-09-16 04:19:50', '2025-09-16 04:19:50'),
(25, 13, 1, 'CWL_1757996552_13_1', 'razorpay', 0.00, 'USD', 'pending', NULL, '2025-09-16 04:22:32', NULL, 0, 3, NULL, 0.00, '', NULL, 0.02, 'order_RI8iNQmIwU23qH', NULL, NULL, '2025-09-16 04:22:32', '2025-09-16 04:22:32'),
(26, 13, 1, 'CWL_1757996574_13_1', 'razorpay', 0.00, 'USD', 'pending', NULL, '2025-09-16 04:22:54', NULL, 0, 3, NULL, 0.00, '', NULL, 0.02, 'order_RI8ilUGnlkBSbG', NULL, NULL, '2025-09-16 04:22:54', '2025-09-16 04:22:54'),
(27, 13, 6, NULL, 'razorpay', 0.00, 'USD', 'completed', NULL, '2025-09-18 05:28:10', '2025-12-17 05:28:10', 0, 3, NULL, 0.00, 'active', NULL, 3.32, 'order_RIwsUk2sjg9DaV', 'pay_RIwsy1ASPq6mev', 'b215ef6973c7a0dddccf1717c504611ae43a823d7e3618f730e6f46d519de5ac', '2025-09-18 05:28:10', '2025-09-18 05:28:10'),
(28, 21, 3, NULL, 'razorpay', 0.00, 'USD', 'completed', NULL, '2025-09-22 12:35:28', '2025-12-21 12:35:28', 0, 3, NULL, 0.00, 'active', NULL, 2.49, 'order_RKeIqL3TLyDSBF', 'pay_RKeJVpIPuXPhTq', '1908a2de3db245e8ba9c3f6da3a333643e0598b090546f4cac50a5b58fba721c', '2025-09-22 12:35:28', '2025-09-22 12:35:28'),
(30, 21, 2, NULL, 'razorpay', 0.00, 'USD', 'completed', NULL, '2025-11-22 13:29:20', '2026-02-20 13:29:20', 0, 3, NULL, 0.00, 'active', NULL, 415.00, 'order_RinoO5V2yRhHTZ', 'pay_RinolwVBuJN18M', '9b8aead28afa667f0184a5585a355640c173b8b1391de3601a378d7f684b1e4a', '2025-11-22 13:29:20', '2025-11-22 13:29:20'),
(31, 52, 1, NULL, 'razorpay', 0.00, 'USD', 'completed', NULL, '2025-11-24 18:17:04', '2026-02-22 18:17:04', 0, 3, NULL, 0.00, 'active', NULL, 4150.00, 'order_RjfmK48VNR2gQh', 'pay_RjfmpzwOpymwUe', '5ad23e2f0f23f8c15a6a4a27c59aa296ee0cd24922383525a19aa655e0c28b70', '2025-11-24 18:17:04', '2025-11-24 18:17:04'),
(32, 59, 1, NULL, 'razorpay', 0.00, 'USD', 'completed', NULL, '2025-11-26 12:15:42', '2026-02-24 12:15:42', 0, 3, NULL, 0.00, 'active', NULL, 3999.00, 'order_RkMgYNOrsuQm4g', 'pay_RkMhTYMApJiGSZ', '38d12dc33d1f6ed0a1eebb98ec5e4b9a21f868b4f48733d5de52e6c943e69452', '2025-11-26 12:15:42', '2025-11-26 12:15:42'),
(34, 109, 1, NULL, 'razorpay', 0.00, 'USD', 'completed', NULL, '2025-12-01 16:04:50', '2026-03-01 16:04:50', 0, 3, NULL, 0.00, 'active', NULL, 1.00, 'order_RmPGdyIcjsEKxp', 'pay_RmPH9T3wuNKuiF', 'd25d0a3b520b59c67b84041e8c4e05b8b741b046bdc8cfe3c419c89c582de776', '2025-12-01 16:04:50', '2025-12-01 16:04:50'),
(35, 110, 1, NULL, 'razorpay', 0.00, 'USD', 'completed', NULL, '2025-12-01 16:21:58', '2026-03-01 16:21:58', 0, 3, NULL, 0.00, 'active', NULL, 1.00, 'order_RmPYsvsdavKDf8', 'pay_RmPZBjWemendu9', '29f87bc054659228bf45818356c948fff61fbadb97f1eb6ca83cbd61f7a61085', '2025-12-01 16:21:58', '2025-12-01 16:21:58'),
(36, 66, 1, NULL, 'razorpay', 0.00, 'USD', 'completed', NULL, '2025-12-01 16:24:52', '2026-03-01 16:24:52', 0, 3, NULL, 0.00, 'active', NULL, 4999.00, 'order_RmPbyYiWKxrLyW', 'pay_RmPcJYXKDH2gmT', 'b0c993399a77a38d46297254fe84d71c28d5ca0495cb572d93c3dca33bef138e', '2025-12-01 16:24:52', '2025-12-01 16:24:52'),
(38, 129, 1, NULL, 'razorpay', 0.00, 'USD', 'completed', NULL, '2025-12-03 05:20:06', '2026-03-03 05:20:06', 0, 3, NULL, 0.00, 'active', NULL, 4999.00, 'order_Rn1Lq2mIBqQD2x', 'pay_Rn1MIv2gZ5wjZp', '41e4474224ea0adabb11d37df4ee60cc0137eafac9153fc691402cc1b89466d4', '2025-12-03 05:20:06', '2025-12-03 05:20:06'),
(40, 65, 1, NULL, 'razorpay', 0.00, 'USD', 'completed', NULL, '2025-12-03 12:19:25', '2026-03-03 12:19:25', 0, 3, NULL, 0.00, 'active', NULL, 1.00, 'order_Rn8UvgBzJFf4iX', 'pay_Rn8VE3lih1W4J5', '32808e2524ec540d59a44dfb70756ad79d1ffe792c07f8dd05c4c138b75a6c0b', '2025-12-03 12:19:25', '2025-12-03 12:19:25'),
(41, 56, 1, NULL, 'razorpay', 0.00, 'USD', 'completed', NULL, '2025-12-03 12:21:07', '2026-03-03 12:21:07', 0, 3, NULL, 0.00, 'active', NULL, 1.00, 'order_Rn8WpTYv8tjPv1', 'pay_Rn8X1VUQ75utDY', '718e6cbcea9c8e49ac1fc2885ea45d8b3c180aea9ebf460dd25143709efe08f0', '2025-12-03 12:21:07', '2025-12-03 12:21:07'),
(42, 141, 1, NULL, 'razorpay', 0.00, 'USD', 'completed', NULL, '2025-12-05 08:27:44', '2026-03-05 08:27:44', 0, 3, NULL, 0.00, 'active', NULL, 1.00, 'order_RnrcGPegmBJoBj', 'pay_Rnrcg6NtJXzdW4', 'bde759cde5e79889175a41efa9bc8317f5e0292cfa558c3172407e80aec9231b', '2025-12-05 08:27:44', '2025-12-05 08:27:44'),
(1024, 27, 1, NULL, 'razorpay', 0.00, 'USD', 'completed', NULL, '2025-12-18 09:09:42', '2026-03-18 09:09:42', 0, 3, NULL, 0.00, 'active', NULL, 1.00, 'order_Rt1H9wgomX5Wxh', 'pay_Rt1He0WpyesXgs', '3674b76740aa575d33e8a0b476de064a1428364f49e5bfdd08498500eadf69f0', '2025-12-18 09:09:42', '2025-12-18 09:09:42'),
(1025, 209, 1, NULL, 'razorpay', 0.00, 'USD', 'completed', NULL, '2026-01-13 15:16:02', '2026-04-13 15:16:02', 0, 3, NULL, 0.00, 'active', NULL, 1.00, 'order_S3PPOPhOEg0Bk5', 'pay_S3PPhHw012OCId', '02cc380c99ab03177d71ca309f9340e75057251516a8d9ff655aae7ddb63ad54', '2026-01-13 15:16:02', '2026-01-13 15:16:02'),
(1026, 230, 1, NULL, 'razorpay', 0.00, 'USD', 'completed', NULL, '2026-01-19 10:19:00', '2026-04-19 10:19:00', 0, 3, NULL, 0.00, 'active', NULL, 1.00, 'order_S5hYBUt0ipiinp', 'pay_S5hYaRI82ZHRJ5', 'b9af5995c63185e4273430d5ecab09bfc52c1147960e31940e5f3de856e7c4b7', '2026-01-19 10:19:00', '2026-01-19 10:19:00'),
(1027, 205, 1, NULL, 'razorpay', 0.00, 'USD', 'completed', NULL, '2026-01-20 11:08:41', '2026-04-20 11:08:41', 0, 3, NULL, 0.00, 'active', NULL, 1.00, 'order_S66vtZ9xKMCOas', 'pay_S66wCI4tn08hjr', 'f57deaad25be197c1ad0c8c38b949881059719c45ed504b89f703c59eb732110', '2026-01-20 11:08:41', '2026-01-20 11:08:41'),
(1028, 241, 1, NULL, 'razorpay', 0.00, 'USD', 'completed', NULL, '2026-01-22 14:35:27', '2026-04-22 14:35:27', 0, 3, NULL, 0.00, 'active', NULL, 1.00, 'order_S6xWZ9zpCoXPlz', 'pay_S6xWqPJkXshWtV', '1230e98c0920c68ea92a07e1020936a42aced33dc393601bbc00c77c52835a21', '2026-01-22 14:35:27', '2026-01-22 14:35:27');

-- --------------------------------------------------------

--
-- Table structure for table `user_sessions`
--

CREATE TABLE `user_sessions` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `session_id` varchar(255) NOT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `user_agent` text DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `last_activity` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `expires_at` timestamp NOT NULL,
  `is_active` tinyint(1) DEFAULT 1
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Triggers `user_sessions`
--
DELIMITER $$
CREATE TRIGGER `cleanup_expired_sessions_trigger` AFTER INSERT ON `user_sessions` FOR EACH ROW BEGIN
  -- Call cleanup procedure
  CALL CleanupExpiredSessions();
END
$$
DELIMITER ;

-- --------------------------------------------------------

--
-- Table structure for table `video_upload_chunks`
--

CREATE TABLE `video_upload_chunks` (
  `id` int(11) NOT NULL,
  `session_id` int(11) NOT NULL,
  `chunk_index` int(11) NOT NULL,
  `chunk_size` int(11) NOT NULL DEFAULT 0,
  `uploaded_at` timestamp NULL DEFAULT current_timestamp(),
  `md5_hash` varchar(32) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `video_upload_sessions`
--

CREATE TABLE `video_upload_sessions` (
  `id` int(11) NOT NULL,
  `session_key` varchar(255) NOT NULL,
  `file_name` varchar(500) NOT NULL,
  `total_chunks` int(11) NOT NULL DEFAULT 0,
  `folder_id` int(11) NOT NULL DEFAULT 1,
  `created_by` int(11) NOT NULL DEFAULT 1,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `started_at` timestamp NULL DEFAULT NULL,
  `completed_at` timestamp NULL DEFAULT NULL,
  `status` enum('preparing','uploading','paused','completed','failed') DEFAULT 'preparing',
  `final_file_id` int(11) DEFAULT NULL,
  `total_size` bigint(20) DEFAULT 0,
  `uploaded_size` bigint(20) DEFAULT 0,
  `last_activity` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Stand-in structure for view `v_active_packages`
-- (See below for the actual view)
--
CREATE TABLE `v_active_packages` (
`id` int(11)
,`package_name` varchar(100)
,`description` text
,`price` decimal(10,2)
,`duration_minutes` int(11)
,`total_questions` int(11)
,`passing_score` int(11)
,`difficulty_level` enum('beginner','intermediate','advanced','expert')
,`is_featured` tinyint(1)
,`category_name` varchar(100)
,`category_slug` varchar(100)
,`icon` varchar(50)
,`color` varchar(20)
);

-- --------------------------------------------------------

--
-- Stand-in structure for view `v_user_stats`
-- (See below for the actual view)
--
CREATE TABLE `v_user_stats` (
`id` int(11)
,`username` varchar(50)
,`full_name` varchar(100)
,`email` varchar(100)
,`created_at` timestamp
,`total_purchases` bigint(21)
,`total_exams` bigint(21)
,`total_certificates` bigint(21)
,`last_exam_date` timestamp
);

--
-- Indexes for dumped tables
--

--
-- Indexes for table `academy_access`
--
ALTER TABLE `academy_access`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_user_id` (`user_id`),
  ADD KEY `idx_certificate_id` (`certificate_id`),
  ADD KEY `idx_access_type` (`access_type`),
  ADD KEY `idx_access_status` (`access_status`),
  ADD KEY `idx_expires_at` (`expires_at`);

--
-- Indexes for table `academy_access_logs`
--
ALTER TABLE `academy_access_logs`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_user_id` (`user_id`),
  ADD KEY `idx_file_id` (`file_id`),
  ADD KEY `idx_content_id` (`content_id`),
  ADD KEY `idx_access_time` (`access_time`),
  ADD KEY `idx_action` (`action`);

--
-- Indexes for table `academy_certificates`
--
ALTER TABLE `academy_certificates`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `unique_academy_certificate_number` (`certificate_number`),
  ADD UNIQUE KEY `unique_academy_verification_code` (`verification_code`),
  ADD KEY `idx_user_cert` (`user_id`,`course_id`),
  ADD KEY `idx_user_package` (`user_id`,`exam_package_id`),
  ADD KEY `idx_status` (`status`),
  ADD KEY `idx_issued_at` (`issued_at`),
  ADD KEY `academy_certificates_ibfk_1` (`course_id`),
  ADD KEY `idx_user_status_created` (`user_id`,`status`,`created_at`);

--
-- Indexes for table `academy_content`
--
ALTER TABLE `academy_content`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_section_id` (`section_id`),
  ADD KEY `idx_content_type` (`content_type`),
  ADD KEY `idx_status` (`status`),
  ADD KEY `idx_sort_order` (`sort_order`),
  ADD KEY `idx_created_by` (`created_by`),
  ADD KEY `idx_academy_content_section_order` (`section_id`,`sort_order`),
  ADD KEY `idx_lms_file_id` (`lms_file_id`);

--
-- Indexes for table `academy_lms_files`
--
ALTER TABLE `academy_lms_files`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_source` (`source`),
  ADD KEY `idx_file_type` (`file_type`),
  ADD KEY `idx_status` (`status`),
  ADD KEY `idx_security_level` (`security_level`),
  ADD KEY `idx_upload_date` (`upload_date`);

--
-- Indexes for table `academy_purchased_courses`
--
ALTER TABLE `academy_purchased_courses`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_user_source` (`user_id`,`source`),
  ADD KEY `idx_course_status` (`course_id`,`status`),
  ADD KEY `idx_exam_package` (`exam_package_id`),
  ADD KEY `idx_purchase_date` (`purchase_date`),
  ADD KEY `idx_certificate` (`certificate_issued`),
  ADD KEY `idx_progress` (`progress`),
  ADD KEY `idx_user_package` (`user_id`,`exam_package_id`),
  ADD KEY `idx_user_course_progress` (`user_id`,`course_id`,`progress`);

--
-- Indexes for table `academy_ratings`
--
ALTER TABLE `academy_ratings`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `unique_user_content_rating` (`user_id`,`content_id`),
  ADD KEY `idx_content_id` (`content_id`),
  ADD KEY `idx_rating` (`rating`),
  ADD KEY `idx_status` (`status`);

--
-- Indexes for table `academy_sections`
--
ALTER TABLE `academy_sections`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_status` (`status`),
  ADD KEY `idx_sort_order` (`sort_order`),
  ADD KEY `idx_created_by` (`created_by`);

--
-- Indexes for table `academy_settings`
--
ALTER TABLE `academy_settings`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `unique_setting_key` (`setting_key`),
  ADD KEY `idx_category` (`category`),
  ADD KEY `idx_public` (`is_public`);

--
-- Indexes for table `academy_user_progress`
--
ALTER TABLE `academy_user_progress`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `unique_user_content` (`user_id`,`content_id`),
  ADD KEY `idx_user_id` (`user_id`),
  ADD KEY `idx_content_id` (`content_id`),
  ADD KEY `idx_completion_status` (`completion_status`),
  ADD KEY `idx_last_accessed` (`last_accessed`),
  ADD KEY `idx_academy_user_progress_user_status` (`user_id`,`completion_status`);

--
-- Indexes for table `access_tokens`
--
ALTER TABLE `access_tokens`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `token` (`token`),
  ADD KEY `idx_token` (`token`),
  ADD KEY `idx_user_id` (`user_id`),
  ADD KEY `idx_expires` (`expires_at`);

--
-- Indexes for table `activity_logs`
--
ALTER TABLE `activity_logs`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_user_id` (`user_id`),
  ADD KEY `idx_action` (`action`),
  ADD KEY `idx_created_at` (`created_at`),
  ADD KEY `idx_entity` (`entity_type`,`entity_id`),
  ADD KEY `idx_activity_logs_date` (`created_at`);

--
-- Indexes for table `admin_credentials`
--
ALTER TABLE `admin_credentials`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `admin_login_tokens`
--
ALTER TABLE `admin_login_tokens`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `token` (`token`),
  ADD KEY `user_id` (`user_id`),
  ADD KEY `expires_at` (`expires_at`),
  ADD KEY `token_type` (`token_type`);

--
-- Indexes for table `admin_notifications`
--
ALTER TABLE `admin_notifications`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_type` (`type`),
  ADD KEY `idx_status` (`status`),
  ADD KEY `idx_created_at` (`created_at`);

--
-- Indexes for table `api_access_patterns`
--
ALTER TABLE `api_access_patterns`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_user_endpoint` (`user_id`,`endpoint`),
  ADD KEY `idx_ip_address` (`ip_address`),
  ADD KEY `idx_status_code` (`status_code`),
  ADD KEY `idx_created_at` (`created_at`),
  ADD KEY `idx_anomaly_score` (`anomaly_score`);

--
-- Indexes for table `certificates`
--
ALTER TABLE `certificates`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `certificate_number` (`certificate_number`),
  ADD UNIQUE KEY `verification_code` (`verification_code`),
  ADD KEY `exam_session_id` (`exam_session_id`),
  ADD KEY `package_id` (`package_id`),
  ADD KEY `idx_user` (`user_id`),
  ADD KEY `idx_certificate_number` (`certificate_number`),
  ADD KEY `idx_verification_code` (`verification_code`),
  ADD KEY `idx_status` (`status`),
  ADD KEY `idx_issued_date` (`issued_date`),
  ADD KEY `idx_certificates_issued_date` (`issued_date`);

--
-- Indexes for table `certificate_audit_log`
--
ALTER TABLE `certificate_audit_log`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_certificate_id` (`certificate_id`),
  ADD KEY `idx_admin_id` (`admin_id`),
  ADD KEY `idx_action` (`action`),
  ADD KEY `idx_created_at` (`created_at`);

--
-- Indexes for table `certificate_resources`
--
ALTER TABLE `certificate_resources`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_certificate_code` (`certificate_code`),
  ADD KEY `idx_status` (`status`),
  ADD KEY `idx_sort_order` (`sort_order`);

--
-- Indexes for table `certificate_settings`
--
ALTER TABLE `certificate_settings`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `certificate_code` (`certificate_code`),
  ADD KEY `idx_certificate_code` (`certificate_code`),
  ADD KEY `idx_package_id` (`package_id`);

--
-- Indexes for table `certificate_validation_cache`
--
ALTER TABLE `certificate_validation_cache`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `unique_user_cert` (`user_id`,`certificate_code`),
  ADD KEY `idx_certificate_code` (`certificate_code`),
  ADD KEY `idx_expires_at` (`expires_at`);

--
-- Indexes for table `cleanup_log_settings`
--
ALTER TABLE `cleanup_log_settings`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `setting_name` (`setting_name`),
  ADD UNIQUE KEY `unique_setting` (`setting_name`);

--
-- Indexes for table `comment_likes`
--
ALTER TABLE `comment_likes`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `unique_user_comment` (`comment_id`,`user_id`),
  ADD KEY `idx_comment_id` (`comment_id`),
  ADD KEY `idx_user_id` (`user_id`);

--
-- Indexes for table `completion_tokens`
--
ALTER TABLE `completion_tokens`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `unique_token` (`token`),
  ADD KEY `idx_user_content` (`user_id`,`content_id`),
  ADD KEY `idx_expires_at` (`expires_at`);

--
-- Indexes for table `contact_messages`
--
ALTER TABLE `contact_messages`
  ADD PRIMARY KEY (`id`),
  ADD KEY `replied_by` (`replied_by`),
  ADD KEY `assigned_to` (`assigned_to`),
  ADD KEY `idx_status` (`status`),
  ADD KEY `idx_priority` (`priority`),
  ADD KEY `idx_created_at` (`created_at`),
  ADD KEY `idx_email` (`email`),
  ADD KEY `idx_contact_priority` (`priority`,`status`),
  ADD KEY `client_access_key` (`client_access_key`);

--
-- Indexes for table `contact_message_replies`
--
ALTER TABLE `contact_message_replies`
  ADD PRIMARY KEY (`id`),
  ADD KEY `contact_message_id` (`contact_message_id`),
  ADD KEY `sender_type` (`sender_type`),
  ADD KEY `created_at` (`created_at`);

--
-- Indexes for table `content_comments`
--
ALTER TABLE `content_comments`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_content_id` (`content_id`),
  ADD KEY `idx_package_id` (`package_id`),
  ADD KEY `idx_user_id` (`user_id`),
  ADD KEY `idx_parent_id` (`parent_id`),
  ADD KEY `idx_status` (`status`),
  ADD KEY `idx_created_at` (`created_at`),
  ADD KEY `idx_content_package` (`content_id`,`package_id`);

--
-- Indexes for table `coupons`
--
ALTER TABLE `coupons`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `code` (`code`),
  ADD KEY `idx_code` (`code`),
  ADD KEY `idx_status` (`status`),
  ADD KEY `idx_valid_from` (`valid_from`),
  ADD KEY `idx_valid_until` (`valid_until`),
  ADD KEY `created_by` (`created_by`);

--
-- Indexes for table `coupon_usage`
--
ALTER TABLE `coupon_usage`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `unique_user_coupon` (`user_id`,`coupon_id`),
  ADD KEY `idx_coupon_id` (`coupon_id`),
  ADD KEY `idx_user_id` (`user_id`),
  ADD KEY `idx_purchase_id` (`purchase_id`);

--
-- Indexes for table `courses`
--
ALTER TABLE `courses`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_category` (`category`),
  ADD KEY `idx_status` (`status`),
  ADD KEY `idx_level` (`level`),
  ADD KEY `idx_featured` (`featured`),
  ADD KEY `idx_rating` (`rating`),
  ADD KEY `idx_created_at` (`created_at`),
  ADD KEY `idx_source_package` (`source_package_id`),
  ADD KEY `idx_enrollments` (`enrollments`);
ALTER TABLE `courses` ADD FULLTEXT KEY `idx_search` (`title`,`description`,`short_description`);

--
-- Indexes for table `course_lessons`
--
ALTER TABLE `course_lessons`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_section_order` (`section_id`,`sort_order`),
  ADD KEY `idx_lms_file` (`lms_file_id`),
  ADD KEY `idx_source_type` (`source_type`),
  ADD KEY `idx_section_id` (`section_id`);

--
-- Indexes for table `course_package_mapping`
--
ALTER TABLE `course_package_mapping`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `unique_package_mapping` (`exam_package_id`),
  ADD KEY `idx_map_type` (`map_type`),
  ADD KEY `idx_status` (`status`),
  ADD KEY `idx_academy_course` (`academy_course_id`);

--
-- Indexes for table `course_sections`
--
ALTER TABLE `course_sections`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_course_order` (`course_id`,`sort_order`),
  ADD KEY `idx_course_id` (`course_id`);

--
-- Indexes for table `device_fingerprints`
--
ALTER TABLE `device_fingerprints`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_user_fingerprint` (`user_id`,`fingerprint_hash`),
  ADD KEY `idx_last_seen` (`last_seen`);

--
-- Indexes for table `discount_banners`
--
ALTER TABLE `discount_banners`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_is_active` (`is_active`),
  ADD KEY `idx_dates` (`start_date`,`end_date`),
  ADD KEY `idx_display_order` (`display_order`);

--
-- Indexes for table `email_otp_verifications`
--
ALTER TABLE `email_otp_verifications`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_email` (`email`),
  ADD KEY `idx_otp_code` (`otp_code`),
  ADD KEY `idx_expires_at` (`expires_at`),
  ADD KEY `idx_is_verified` (`is_verified`);

--
-- Indexes for table `email_queue`
--
ALTER TABLE `email_queue`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_status` (`status`),
  ADD KEY `idx_created_at` (`created_at`),
  ADD KEY `idx_recipient_email` (`recipient_email`);

--
-- Indexes for table `enhanced_security_events`
--
ALTER TABLE `enhanced_security_events`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_user_events` (`user_id`,`created_at`),
  ADD KEY `idx_event_type` (`event_type`),
  ADD KEY `idx_ip_address` (`ip_address`),
  ADD KEY `idx_created_at` (`created_at`);

--
-- Indexes for table `exam_attempts`
--
ALTER TABLE `exam_attempts`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_user_id` (`user_id`),
  ADD KEY `idx_package_id` (`package_id`),
  ADD KEY `idx_session_id` (`session_id`),
  ADD KEY `idx_status` (`status`);

--
-- Indexes for table `exam_categories`
--
ALTER TABLE `exam_categories`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `category_slug` (`category_slug`),
  ADD KEY `idx_status` (`status`),
  ADD KEY `idx_display_order` (`display_order`);

--
-- Indexes for table `exam_packages`
--
ALTER TABLE `exam_packages`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_category` (`category_id`),
  ADD KEY `idx_status` (`status`),
  ADD KEY `idx_featured` (`is_featured`),
  ADD KEY `idx_difficulty` (`difficulty_level`);

--
-- Indexes for table `exam_questions`
--
ALTER TABLE `exam_questions`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `exam_results`
--
ALTER TABLE `exam_results`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `exam_schedules`
--
ALTER TABLE `exam_schedules`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `unique_exam_date` (`exam_date`),
  ADD KEY `idx_exam_date` (`exam_date`),
  ADD KEY `idx_status` (`status`),
  ADD KEY `created_by` (`created_by`);

--
-- Indexes for table `exam_sessions`
--
ALTER TABLE `exam_sessions`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `session_token` (`session_token`),
  ADD KEY `purchase_id` (`purchase_id`),
  ADD KEY `idx_user` (`user_id`),
  ADD KEY `idx_package` (`package_id`),
  ADD KEY `idx_session_token` (`session_token`),
  ADD KEY `idx_status` (`status`),
  ADD KEY `idx_result` (`result`),
  ADD KEY `idx_scheduled_date` (`scheduled_date`),
  ADD KEY `idx_sessions_created_at` (`created_at`);

--
-- Indexes for table `exam_time_slots`
--
ALTER TABLE `exam_time_slots`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `unique_schedule_time` (`schedule_id`,`time_slot`),
  ADD KEY `idx_schedule_id` (`schedule_id`),
  ADD KEY `idx_time_slot` (`time_slot`),
  ADD KEY `idx_status` (`status`);

--
-- Indexes for table `file_access_nonces`
--
ALTER TABLE `file_access_nonces`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `nonce` (`nonce`),
  ADD KEY `idx_nonce` (`nonce`),
  ADD KEY `idx_user_file` (`user_id`,`file_id`),
  ADD KEY `idx_expires` (`expires_at`),
  ADD KEY `idx_used` (`used`);

--
-- Indexes for table `file_access_tokens`
--
ALTER TABLE `file_access_tokens`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `token` (`token`),
  ADD KEY `idx_token` (`token`),
  ADD KEY `idx_file_user` (`file_id`,`user_id`);

--
-- Indexes for table `lms_access_logs`
--
ALTER TABLE `lms_access_logs`
  ADD PRIMARY KEY (`id`),
  ADD KEY `user_id` (`user_id`),
  ADD KEY `folder_id` (`folder_id`),
  ADD KEY `file_id` (`file_id`),
  ADD KEY `action` (`action`),
  ADD KEY `access_time` (`access_time`);

--
-- Indexes for table `lms_download_tokens`
--
ALTER TABLE `lms_download_tokens`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `token` (`token`),
  ADD KEY `file_id` (`file_id`),
  ADD KEY `user_id` (`user_id`),
  ADD KEY `expires_at` (`expires_at`);

--
-- Indexes for table `lms_files`
--
ALTER TABLE `lms_files`
  ADD PRIMARY KEY (`id`),
  ADD KEY `folder_id` (`folder_id`),
  ADD KEY `file_type` (`file_type`),
  ADD KEY `idx_security_level` (`security_level`),
  ADD KEY `idx_last_accessed` (`last_accessed`);

--
-- Indexes for table `lms_file_tags`
--
ALTER TABLE `lms_file_tags`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `unique_file_tag` (`file_id`,`tag_name`),
  ADD KEY `idx_tag_name` (`tag_name`);

--
-- Indexes for table `lms_folders`
--
ALTER TABLE `lms_folders`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `unique_folder_slug` (`folder_slug`),
  ADD KEY `parent_id` (`parent_id`),
  ADD KEY `idx_security_level` (`security_level`);

--
-- Indexes for table `lms_folder_permissions`
--
ALTER TABLE `lms_folder_permissions`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `unique_folder_permission` (`folder_id`,`access_type`),
  ADD KEY `folder_id` (`folder_id`),
  ADD KEY `access_type` (`access_type`);

--
-- Indexes for table `lms_security_events`
--
ALTER TABLE `lms_security_events`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_user_id` (`user_id`),
  ADD KEY `idx_file_id` (`file_id`),
  ADD KEY `idx_event_type` (`event_type`),
  ADD KEY `idx_event_time` (`event_time`),
  ADD KEY `idx_ip_address` (`ip_address`);

--
-- Indexes for table `lms_settings`
--
ALTER TABLE `lms_settings`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `setting_key` (`setting_key`),
  ADD KEY `idx_setting_key` (`setting_key`);

--
-- Indexes for table `lms_upload_sessions`
--
ALTER TABLE `lms_upload_sessions`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `upload_id` (`upload_id`),
  ADD KEY `folder_id` (`folder_id`),
  ADD KEY `user_id` (`user_id`),
  ADD KEY `status` (`status`),
  ADD KEY `created_at` (`created_at`);

--
-- Indexes for table `login_attempts`
--
ALTER TABLE `login_attempts`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `password_resets`
--
ALTER TABLE `password_resets`
  ADD PRIMARY KEY (`id`),
  ADD KEY `user_id` (`user_id`),
  ADD KEY `idx_token` (`token`),
  ADD KEY `idx_email` (`email`);

--
-- Indexes for table `payment_logs`
--
ALTER TABLE `payment_logs`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_user_id` (`user_id`),
  ADD KEY `idx_created_at` (`created_at`);

--
-- Indexes for table `purchased_courses`
--
ALTER TABLE `purchased_courses`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_user_source` (`user_id`,`source`),
  ADD KEY `idx_course_status` (`course_id`,`status`),
  ADD KEY `idx_exam_package` (`exam_package_id`),
  ADD KEY `idx_purchase_date` (`purchase_date`),
  ADD KEY `idx_certificate` (`certificate_issued`),
  ADD KEY `idx_progress` (`progress`),
  ADD KEY `idx_user_package` (`user_id`,`exam_package_id`),
  ADD KEY `idx_user_course_progress` (`user_id`,`course_id`,`progress`);

--
-- Indexes for table `questions`
--
ALTER TABLE `questions`
  ADD PRIMARY KEY (`id`),
  ADD KEY `created_by` (`created_by`),
  ADD KEY `idx_category` (`category_id`),
  ADD KEY `idx_package` (`package_id`),
  ADD KEY `idx_difficulty` (`difficulty`),
  ADD KEY `idx_status` (`status`);

--
-- Indexes for table `rate_limits`
--
ALTER TABLE `rate_limits`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `unique_ip_action` (`ip_address`,`action_type`,`window_start`),
  ADD KEY `idx_ip_blocked` (`ip_address`,`blocked_until`);

--
-- Indexes for table `remember_tokens`
--
ALTER TABLE `remember_tokens`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_user_id` (`user_id`),
  ADD KEY `idx_token` (`token`),
  ADD KEY `idx_expires_at` (`expires_at`);

--
-- Indexes for table `secure_file_access_logs`
--
ALTER TABLE `secure_file_access_logs`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_user_id` (`user_id`),
  ADD KEY `idx_access_time` (`access_time`);

--
-- Indexes for table `secure_file_tokens`
--
ALTER TABLE `secure_file_tokens`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `unique_token` (`token`),
  ADD KEY `idx_user_id` (`user_id`),
  ADD KEY `idx_expires` (`expires_at`);

--
-- Indexes for table `secure_preview_tokens`
--
ALTER TABLE `secure_preview_tokens`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `unique_token_hash` (`token_hash`),
  ADD KEY `idx_user_file` (`user_id`,`file_id`),
  ADD KEY `idx_session_id` (`session_id`),
  ADD KEY `idx_expires_at` (`expires_at`),
  ADD KEY `idx_ip_address` (`ip_address`);

--
-- Indexes for table `secure_tokens`
--
ALTER TABLE `secure_tokens`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `token` (`token`),
  ADD KEY `idx_token` (`token`),
  ADD KEY `idx_expires_at` (`expires_at`),
  ADD KEY `idx_user_id` (`user_id`);

--
-- Indexes for table `security_events`
--
ALTER TABLE `security_events`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_event_type` (`event_type`),
  ADD KEY `idx_user_id` (`user_id`),
  ADD KEY `idx_ip_address` (`ip_address`),
  ADD KEY `idx_created_at` (`created_at`),
  ADD KEY `idx_severity` (`severity`),
  ADD KEY `idx_resolved` (`resolved`);

--
-- Indexes for table `session_security`
--
ALTER TABLE `session_security`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `unique_session` (`session_id`),
  ADD KEY `idx_user_id` (`user_id`),
  ADD KEY `idx_ip_address` (`ip_address`),
  ADD KEY `idx_last_activity` (`last_activity`),
  ADD KEY `idx_is_secure` (`is_secure`);

--
-- Indexes for table `site_settings`
--
ALTER TABLE `site_settings`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `setting_key` (`setting_key`),
  ADD KEY `idx_category` (`category`),
  ADD KEY `idx_public` (`is_public`);

--
-- Indexes for table `suspicious_patterns`
--
ALTER TABLE `suspicious_patterns`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_pattern_type` (`pattern_type`),
  ADD KEY `idx_ip_address` (`ip_address`),
  ADD KEY `idx_user_id` (`user_id`),
  ADD KEY `idx_risk_score` (`risk_score`),
  ADD KEY `idx_active` (`active`);

--
-- Indexes for table `system_settings`
--
ALTER TABLE `system_settings`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `setting_key` (`setting_key`),
  ADD KEY `idx_setting_key` (`setting_key`),
  ADD KEY `idx_category` (`category`);

--
-- Indexes for table `target_ips`
--
ALTER TABLE `target_ips`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `time_based_access`
--
ALTER TABLE `time_based_access`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `unique_token_file` (`access_token`,`file_id`);

--
-- Indexes for table `time_based_tokens`
--
ALTER TABLE `time_based_tokens`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `token_id` (`token_id`),
  ADD KEY `idx_user_resource` (`user_id`,`resource_type`,`resource_id`),
  ADD KEY `idx_expires` (`expires_at`),
  ADD KEY `idx_status` (`status`);

--
-- Indexes for table `upload_analytics`
--
ALTER TABLE `upload_analytics`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_session_key` (`session_key`),
  ADD KEY `idx_file_type` (`file_type`),
  ADD KEY `idx_upload_method` (`upload_method`),
  ADD KEY `idx_user_id` (`user_id`),
  ADD KEY `idx_status` (`status`),
  ADD KEY `idx_start_time` (`start_time`);

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `username` (`username`),
  ADD UNIQUE KEY `email` (`email`),
  ADD KEY `idx_username` (`username`),
  ADD KEY `idx_email` (`email`),
  ADD KEY `idx_status` (`status`),
  ADD KEY `idx_user_type` (`user_type`),
  ADD KEY `idx_email_verified` (`email_verified`),
  ADD KEY `idx_users_created_at` (`created_at`),
  ADD KEY `idx_last_login` (`last_login`),
  ADD KEY `idx_failed_attempts` (`failed_attempts`),
  ADD KEY `idx_locked_until` (`locked_until`);

--
-- Indexes for table `user_completed_lessons`
--
ALTER TABLE `user_completed_lessons`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `unique_user_content` (`user_id`,`content_id`),
  ADD KEY `idx_user_id` (`user_id`),
  ADD KEY `idx_content_id` (`content_id`),
  ADD KEY `idx_package_id` (`package_id`),
  ADD KEY `idx_completion_token` (`completion_token`);

--
-- Indexes for table `user_lessons`
--
ALTER TABLE `user_lessons`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `unique_user_lesson` (`user_id`,`lesson_id`),
  ADD KEY `idx_user_lesson` (`user_id`,`lesson_id`),
  ADD KEY `idx_completed_at` (`completed_at`),
  ADD KEY `idx_lesson_id` (`lesson_id`),
  ADD KEY `idx_user_completion` (`user_id`,`completed_at`);

--
-- Indexes for table `user_purchases`
--
ALTER TABLE `user_purchases`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `transaction_id` (`transaction_id`),
  ADD KEY `idx_user` (`user_id`),
  ADD KEY `idx_package` (`package_id`),
  ADD KEY `idx_payment_status` (`payment_status`),
  ADD KEY `idx_status` (`status`),
  ADD KEY `idx_transaction` (`transaction_id`),
  ADD KEY `idx_purchases_date` (`purchase_date`),
  ADD KEY `idx_razorpay_order` (`razorpay_order_id`),
  ADD KEY `idx_razorpay_payment` (`razorpay_payment_id`),
  ADD KEY `idx_user_package` (`user_id`,`package_id`);

--
-- Indexes for table `user_sessions`
--
ALTER TABLE `user_sessions`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `unique_user_session` (`user_id`,`is_active`),
  ADD KEY `idx_session_id` (`session_id`),
  ADD KEY `idx_user_id` (`user_id`),
  ADD KEY `idx_expires_at` (`expires_at`),
  ADD KEY `idx_last_activity` (`last_activity`);

--
-- Indexes for table `video_upload_chunks`
--
ALTER TABLE `video_upload_chunks`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `unique_chunk` (`session_id`,`chunk_index`),
  ADD KEY `idx_session_id` (`session_id`),
  ADD KEY `idx_chunk_index` (`chunk_index`);

--
-- Indexes for table `video_upload_sessions`
--
ALTER TABLE `video_upload_sessions`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_session_key` (`session_key`),
  ADD KEY `idx_status` (`status`),
  ADD KEY `idx_created_by` (`created_by`),
  ADD KEY `idx_folder_id` (`folder_id`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `academy_access`
--
ALTER TABLE `academy_access`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=12;

--
-- AUTO_INCREMENT for table `academy_access_logs`
--
ALTER TABLE `academy_access_logs`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `academy_certificates`
--
ALTER TABLE `academy_certificates`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `academy_content`
--
ALTER TABLE `academy_content`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=197;

--
-- AUTO_INCREMENT for table `academy_lms_files`
--
ALTER TABLE `academy_lms_files`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `academy_purchased_courses`
--
ALTER TABLE `academy_purchased_courses`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `academy_ratings`
--
ALTER TABLE `academy_ratings`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `academy_sections`
--
ALTER TABLE `academy_sections`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=44;

--
-- AUTO_INCREMENT for table `academy_settings`
--
ALTER TABLE `academy_settings`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=19;

--
-- AUTO_INCREMENT for table `academy_user_progress`
--
ALTER TABLE `academy_user_progress`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `access_tokens`
--
ALTER TABLE `access_tokens`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `activity_logs`
--
ALTER TABLE `activity_logs`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=485;

--
-- AUTO_INCREMENT for table `admin_credentials`
--
ALTER TABLE `admin_credentials`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT for table `admin_login_tokens`
--
ALTER TABLE `admin_login_tokens`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `admin_notifications`
--
ALTER TABLE `admin_notifications`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `api_access_patterns`
--
ALTER TABLE `api_access_patterns`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `certificates`
--
ALTER TABLE `certificates`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=37;

--
-- AUTO_INCREMENT for table `certificate_audit_log`
--
ALTER TABLE `certificate_audit_log`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `certificate_resources`
--
ALTER TABLE `certificate_resources`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=9;

--
-- AUTO_INCREMENT for table `certificate_settings`
--
ALTER TABLE `certificate_settings`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=17;

--
-- AUTO_INCREMENT for table `certificate_validation_cache`
--
ALTER TABLE `certificate_validation_cache`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `cleanup_log_settings`
--
ALTER TABLE `cleanup_log_settings`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=17;

--
-- AUTO_INCREMENT for table `comment_likes`
--
ALTER TABLE `comment_likes`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `completion_tokens`
--
ALTER TABLE `completion_tokens`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `contact_messages`
--
ALTER TABLE `contact_messages`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=90918;

--
-- AUTO_INCREMENT for table `contact_message_replies`
--
ALTER TABLE `contact_message_replies`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=3;

--
-- AUTO_INCREMENT for table `content_comments`
--
ALTER TABLE `content_comments`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=168;

--
-- AUTO_INCREMENT for table `coupons`
--
ALTER TABLE `coupons`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `coupon_usage`
--
ALTER TABLE `coupon_usage`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `courses`
--
ALTER TABLE `courses`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `course_lessons`
--
ALTER TABLE `course_lessons`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `course_package_mapping`
--
ALTER TABLE `course_package_mapping`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `course_sections`
--
ALTER TABLE `course_sections`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `device_fingerprints`
--
ALTER TABLE `device_fingerprints`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `discount_banners`
--
ALTER TABLE `discount_banners`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=7;

--
-- AUTO_INCREMENT for table `email_otp_verifications`
--
ALTER TABLE `email_otp_verifications`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=410;

--
-- AUTO_INCREMENT for table `email_queue`
--
ALTER TABLE `email_queue`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `enhanced_security_events`
--
ALTER TABLE `enhanced_security_events`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `exam_attempts`
--
ALTER TABLE `exam_attempts`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `exam_categories`
--
ALTER TABLE `exam_categories`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=7;

--
-- AUTO_INCREMENT for table `exam_packages`
--
ALTER TABLE `exam_packages`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=9;

--
-- AUTO_INCREMENT for table `exam_questions`
--
ALTER TABLE `exam_questions`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=20;

--
-- AUTO_INCREMENT for table `exam_results`
--
ALTER TABLE `exam_results`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `exam_schedules`
--
ALTER TABLE `exam_schedules`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=54;

--
-- AUTO_INCREMENT for table `exam_sessions`
--
ALTER TABLE `exam_sessions`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=21;

--
-- AUTO_INCREMENT for table `exam_time_slots`
--
ALTER TABLE `exam_time_slots`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=282;

--
-- AUTO_INCREMENT for table `file_access_nonces`
--
ALTER TABLE `file_access_nonces`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `file_access_tokens`
--
ALTER TABLE `file_access_tokens`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=3;

--
-- AUTO_INCREMENT for table `lms_access_logs`
--
ALTER TABLE `lms_access_logs`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=7031;

--
-- AUTO_INCREMENT for table `lms_download_tokens`
--
ALTER TABLE `lms_download_tokens`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `lms_files`
--
ALTER TABLE `lms_files`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=223;

--
-- AUTO_INCREMENT for table `lms_file_tags`
--
ALTER TABLE `lms_file_tags`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `lms_folders`
--
ALTER TABLE `lms_folders`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=54;

--
-- AUTO_INCREMENT for table `lms_folder_permissions`
--
ALTER TABLE `lms_folder_permissions`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=179;

--
-- AUTO_INCREMENT for table `lms_security_events`
--
ALTER TABLE `lms_security_events`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=9;

--
-- AUTO_INCREMENT for table `lms_settings`
--
ALTER TABLE `lms_settings`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=15;

--
-- AUTO_INCREMENT for table `lms_upload_sessions`
--
ALTER TABLE `lms_upload_sessions`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=30;

--
-- AUTO_INCREMENT for table `login_attempts`
--
ALTER TABLE `login_attempts`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `password_resets`
--
ALTER TABLE `password_resets`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=29;

--
-- AUTO_INCREMENT for table `payment_logs`
--
ALTER TABLE `payment_logs`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `purchased_courses`
--
ALTER TABLE `purchased_courses`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `questions`
--
ALTER TABLE `questions`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=6;

--
-- AUTO_INCREMENT for table `rate_limits`
--
ALTER TABLE `rate_limits`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `remember_tokens`
--
ALTER TABLE `remember_tokens`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=334;

--
-- AUTO_INCREMENT for table `secure_file_access_logs`
--
ALTER TABLE `secure_file_access_logs`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `secure_file_tokens`
--
ALTER TABLE `secure_file_tokens`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `secure_preview_tokens`
--
ALTER TABLE `secure_preview_tokens`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=175;

--
-- AUTO_INCREMENT for table `secure_tokens`
--
ALTER TABLE `secure_tokens`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `security_events`
--
ALTER TABLE `security_events`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=11;

--
-- AUTO_INCREMENT for table `session_security`
--
ALTER TABLE `session_security`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `site_settings`
--
ALTER TABLE `site_settings`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=33;

--
-- AUTO_INCREMENT for table `suspicious_patterns`
--
ALTER TABLE `suspicious_patterns`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `system_settings`
--
ALTER TABLE `system_settings`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=6;

--
-- AUTO_INCREMENT for table `target_ips`
--
ALTER TABLE `target_ips`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=3;

--
-- AUTO_INCREMENT for table `time_based_access`
--
ALTER TABLE `time_based_access`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `time_based_tokens`
--
ALTER TABLE `time_based_tokens`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `upload_analytics`
--
ALTER TABLE `upload_analytics`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `users`
--
ALTER TABLE `users`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=305;

--
-- AUTO_INCREMENT for table `user_completed_lessons`
--
ALTER TABLE `user_completed_lessons`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=131;

--
-- AUTO_INCREMENT for table `user_lessons`
--
ALTER TABLE `user_lessons`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `user_purchases`
--
ALTER TABLE `user_purchases`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=1029;

--
-- AUTO_INCREMENT for table `user_sessions`
--
ALTER TABLE `user_sessions`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2310;

--
-- AUTO_INCREMENT for table `video_upload_chunks`
--
ALTER TABLE `video_upload_chunks`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `video_upload_sessions`
--
ALTER TABLE `video_upload_sessions`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

-- --------------------------------------------------------

--
-- Structure for view `academy_user_access_view`
--
DROP TABLE IF EXISTS `academy_user_access_view`;

CREATE ALGORITHM=UNDEFINED DEFINER=`u944542294_cyberwarlab`@`localhost` SQL SECURITY DEFINER VIEW `academy_user_access_view`  AS SELECT `u`.`id` AS `user_id`, `u`.`username` AS `username`, `u`.`email` AS `email`, coalesce(`aa`.`access_status`,'none') AS `access_status`, coalesce(`aa`.`expires_at`,NULL) AS `access_expires_at`, CASE WHEN `aa`.`id` is not null AND `aa`.`access_status` = 'active' AND (`aa`.`expires_at` is null OR `aa`.`expires_at` > current_timestamp()) THEN 1 ELSE 0 END AS `has_access` FROM (`users` `u` left join `academy_access` `aa` on(`u`.`id` = `aa`.`user_id` and `aa`.`access_status` = 'active' and (`aa`.`expires_at` is null or `aa`.`expires_at` > current_timestamp()))) WHERE `u`.`status` = 'active' ;

-- --------------------------------------------------------

--
-- Structure for view `security_dashboard`
--
DROP TABLE IF EXISTS `security_dashboard`;

CREATE ALGORITHM=UNDEFINED DEFINER=`u944542294_cyberwarlab`@`127.0.0.1` SQL SECURITY DEFINER VIEW `security_dashboard`  AS SELECT count(0) AS `total_security_events`, count(case when `security_events`.`severity` = 'critical' then 1 end) AS `critical_events`, count(case when `security_events`.`severity` = 'high' then 1 end) AS `high_events`, count(case when `security_events`.`event_type` in ('session_ip_mismatch','session_ua_mismatch') then 1 end) AS `session_attacks`, count(case when `security_events`.`event_type` in ('invalid_signature','token_reuse_attempt') then 1 end) AS `token_attacks`, count(case when `security_events`.`created_at` > current_timestamp() - interval 1 hour then 1 end) AS `last_hour_events`, count(case when `security_events`.`created_at` > current_timestamp() - interval 24 hour then 1 end) AS `last_24h_events`, count(distinct `security_events`.`ip_address`) AS `unique_ips`, count(distinct `security_events`.`user_id`) AS `affected_users` FROM `security_events` WHERE `security_events`.`created_at` > current_timestamp() - interval 7 day ;

-- --------------------------------------------------------

--
-- Structure for view `v_active_packages`
--
DROP TABLE IF EXISTS `v_active_packages`;

CREATE ALGORITHM=UNDEFINED DEFINER=`u944542294_cyberwarlab`@`127.0.0.1` SQL SECURITY DEFINER VIEW `v_active_packages`  AS SELECT `ep`.`id` AS `id`, `ep`.`package_name` AS `package_name`, `ep`.`description` AS `description`, `ep`.`price` AS `price`, `ep`.`duration_minutes` AS `duration_minutes`, `ep`.`total_questions` AS `total_questions`, `ep`.`passing_score` AS `passing_score`, `ep`.`difficulty_level` AS `difficulty_level`, `ep`.`is_featured` AS `is_featured`, `ec`.`category_name` AS `category_name`, `ec`.`category_slug` AS `category_slug`, `ec`.`icon` AS `icon`, `ec`.`color` AS `color` FROM (`exam_packages` `ep` join `exam_categories` `ec` on(`ep`.`category_id` = `ec`.`id`)) WHERE `ep`.`status` = 'active' AND `ec`.`status` = 'active' ORDER BY `ec`.`display_order` ASC, `ep`.`price` ASC ;

-- --------------------------------------------------------

--
-- Structure for view `v_user_stats`
--
DROP TABLE IF EXISTS `v_user_stats`;

CREATE ALGORITHM=UNDEFINED DEFINER=`u944542294_cyberwarlab`@`127.0.0.1` SQL SECURITY DEFINER VIEW `v_user_stats`  AS SELECT `u`.`id` AS `id`, `u`.`username` AS `username`, `u`.`full_name` AS `full_name`, `u`.`email` AS `email`, `u`.`created_at` AS `created_at`, count(distinct `up`.`id`) AS `total_purchases`, count(distinct `es`.`id`) AS `total_exams`, count(distinct `c`.`id`) AS `total_certificates`, max(`es`.`completed_at`) AS `last_exam_date` FROM (((`users` `u` left join `user_purchases` `up` on(`u`.`id` = `up`.`user_id`)) left join `exam_sessions` `es` on(`u`.`id` = `es`.`user_id`)) left join `certificates` `c` on(`u`.`id` = `c`.`user_id`)) WHERE `u`.`user_type` = 'user' GROUP BY `u`.`id` ;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `academy_access`
--
ALTER TABLE `academy_access`
  ADD CONSTRAINT `academy_access_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `academy_access_logs`
--
ALTER TABLE `academy_access_logs`
  ADD CONSTRAINT `academy_access_logs_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `academy_certificates`
--
ALTER TABLE `academy_certificates`
  ADD CONSTRAINT `academy_certificates_ibfk_1` FOREIGN KEY (`course_id`) REFERENCES `courses` (`id`) ON DELETE SET NULL;

--
-- Constraints for table `academy_content`
--
ALTER TABLE `academy_content`
  ADD CONSTRAINT `academy_content_ibfk_1` FOREIGN KEY (`section_id`) REFERENCES `academy_sections` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `academy_purchased_courses`
--
ALTER TABLE `academy_purchased_courses`
  ADD CONSTRAINT `academy_purchased_courses_ibfk_1` FOREIGN KEY (`course_id`) REFERENCES `courses` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `academy_ratings`
--
ALTER TABLE `academy_ratings`
  ADD CONSTRAINT `academy_ratings_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `academy_ratings_ibfk_2` FOREIGN KEY (`content_id`) REFERENCES `academy_content` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `academy_user_progress`
--
ALTER TABLE `academy_user_progress`
  ADD CONSTRAINT `academy_user_progress_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `academy_user_progress_ibfk_2` FOREIGN KEY (`content_id`) REFERENCES `academy_content` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `activity_logs`
--
ALTER TABLE `activity_logs`
  ADD CONSTRAINT `activity_logs_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE SET NULL;

--
-- Constraints for table `admin_login_tokens`
--
ALTER TABLE `admin_login_tokens`
  ADD CONSTRAINT `admin_login_tokens_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `certificates`
--
ALTER TABLE `certificates`
  ADD CONSTRAINT `certificates_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `certificates_ibfk_2` FOREIGN KEY (`exam_session_id`) REFERENCES `exam_sessions` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `certificates_ibfk_3` FOREIGN KEY (`package_id`) REFERENCES `exam_packages` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `certificate_audit_log`
--
ALTER TABLE `certificate_audit_log`
  ADD CONSTRAINT `fk_audit_admin` FOREIGN KEY (`admin_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `fk_audit_certificate` FOREIGN KEY (`certificate_id`) REFERENCES `certificates` (`certificate_number`) ON DELETE CASCADE;

--
-- Constraints for table `certificate_settings`
--
ALTER TABLE `certificate_settings`
  ADD CONSTRAINT `certificate_settings_ibfk_1` FOREIGN KEY (`package_id`) REFERENCES `exam_packages` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `comment_likes`
--
ALTER TABLE `comment_likes`
  ADD CONSTRAINT `comment_likes_ibfk_1` FOREIGN KEY (`comment_id`) REFERENCES `content_comments` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `comment_likes_ibfk_2` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `contact_messages`
--
ALTER TABLE `contact_messages`
  ADD CONSTRAINT `contact_messages_ibfk_1` FOREIGN KEY (`replied_by`) REFERENCES `users` (`id`) ON DELETE SET NULL,
  ADD CONSTRAINT `contact_messages_ibfk_2` FOREIGN KEY (`assigned_to`) REFERENCES `users` (`id`) ON DELETE SET NULL;

--
-- Constraints for table `contact_message_replies`
--
ALTER TABLE `contact_message_replies`
  ADD CONSTRAINT `contact_message_replies_ibfk_1` FOREIGN KEY (`contact_message_id`) REFERENCES `contact_messages` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `coupons`
--
ALTER TABLE `coupons`
  ADD CONSTRAINT `coupons_ibfk_1` FOREIGN KEY (`created_by`) REFERENCES `users` (`id`) ON DELETE SET NULL;

--
-- Constraints for table `coupon_usage`
--
ALTER TABLE `coupon_usage`
  ADD CONSTRAINT `coupon_usage_ibfk_1` FOREIGN KEY (`coupon_id`) REFERENCES `coupons` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `coupon_usage_ibfk_2` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `coupon_usage_ibfk_3` FOREIGN KEY (`purchase_id`) REFERENCES `user_purchases` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `course_lessons`
--
ALTER TABLE `course_lessons`
  ADD CONSTRAINT `course_lessons_ibfk_1` FOREIGN KEY (`section_id`) REFERENCES `course_sections` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `fk_course_lessons_section` FOREIGN KEY (`section_id`) REFERENCES `course_sections` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `course_package_mapping`
--
ALTER TABLE `course_package_mapping`
  ADD CONSTRAINT `course_package_mapping_ibfk_1` FOREIGN KEY (`academy_course_id`) REFERENCES `courses` (`id`) ON DELETE SET NULL,
  ADD CONSTRAINT `fk_course_package_mapping_course` FOREIGN KEY (`academy_course_id`) REFERENCES `courses` (`id`) ON DELETE SET NULL;

--
-- Constraints for table `course_sections`
--
ALTER TABLE `course_sections`
  ADD CONSTRAINT `course_sections_ibfk_1` FOREIGN KEY (`course_id`) REFERENCES `courses` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `fk_course_sections_course` FOREIGN KEY (`course_id`) REFERENCES `courses` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `exam_attempts`
--
ALTER TABLE `exam_attempts`
  ADD CONSTRAINT `exam_attempts_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `exam_attempts_ibfk_2` FOREIGN KEY (`package_id`) REFERENCES `exam_packages` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `exam_attempts_ibfk_3` FOREIGN KEY (`session_id`) REFERENCES `exam_sessions` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `exam_packages`
--
ALTER TABLE `exam_packages`
  ADD CONSTRAINT `exam_packages_ibfk_1` FOREIGN KEY (`category_id`) REFERENCES `exam_categories` (`id`) ON DELETE SET NULL;

--
-- Constraints for table `exam_schedules`
--
ALTER TABLE `exam_schedules`
  ADD CONSTRAINT `exam_schedules_ibfk_1` FOREIGN KEY (`created_by`) REFERENCES `users` (`id`) ON DELETE SET NULL;

--
-- Constraints for table `exam_sessions`
--
ALTER TABLE `exam_sessions`
  ADD CONSTRAINT `exam_sessions_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `exam_sessions_ibfk_2` FOREIGN KEY (`package_id`) REFERENCES `exam_packages` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `exam_sessions_ibfk_3` FOREIGN KEY (`purchase_id`) REFERENCES `user_purchases` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `exam_time_slots`
--
ALTER TABLE `exam_time_slots`
  ADD CONSTRAINT `exam_time_slots_ibfk_1` FOREIGN KEY (`schedule_id`) REFERENCES `exam_schedules` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `lms_files`
--
ALTER TABLE `lms_files`
  ADD CONSTRAINT `lms_files_ibfk_1` FOREIGN KEY (`folder_id`) REFERENCES `lms_folders` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `lms_file_tags`
--
ALTER TABLE `lms_file_tags`
  ADD CONSTRAINT `lms_file_tags_ibfk_1` FOREIGN KEY (`file_id`) REFERENCES `lms_files` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `lms_folders`
--
ALTER TABLE `lms_folders`
  ADD CONSTRAINT `lms_folders_ibfk_1` FOREIGN KEY (`parent_id`) REFERENCES `lms_folders` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `lms_folder_permissions`
--
ALTER TABLE `lms_folder_permissions`
  ADD CONSTRAINT `lms_folder_permissions_ibfk_1` FOREIGN KEY (`folder_id`) REFERENCES `lms_folders` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `password_resets`
--
ALTER TABLE `password_resets`
  ADD CONSTRAINT `password_resets_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `payment_logs`
--
ALTER TABLE `payment_logs`
  ADD CONSTRAINT `payment_logs_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `purchased_courses`
--
ALTER TABLE `purchased_courses`
  ADD CONSTRAINT `purchased_courses_ibfk_1` FOREIGN KEY (`course_id`) REFERENCES `courses` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `questions`
--
ALTER TABLE `questions`
  ADD CONSTRAINT `questions_ibfk_1` FOREIGN KEY (`category_id`) REFERENCES `exam_categories` (`id`) ON DELETE SET NULL,
  ADD CONSTRAINT `questions_ibfk_2` FOREIGN KEY (`package_id`) REFERENCES `exam_packages` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `questions_ibfk_3` FOREIGN KEY (`created_by`) REFERENCES `users` (`id`) ON DELETE SET NULL;

--
-- Constraints for table `remember_tokens`
--
ALTER TABLE `remember_tokens`
  ADD CONSTRAINT `remember_tokens_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `time_based_tokens`
--
ALTER TABLE `time_based_tokens`
  ADD CONSTRAINT `time_based_tokens_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `user_lessons`
--
ALTER TABLE `user_lessons`
  ADD CONSTRAINT `user_lessons_ibfk_1` FOREIGN KEY (`lesson_id`) REFERENCES `course_lessons` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `user_purchases`
--
ALTER TABLE `user_purchases`
  ADD CONSTRAINT `user_purchases_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `user_purchases_ibfk_2` FOREIGN KEY (`package_id`) REFERENCES `exam_packages` (`id`) ON DELETE CASCADE;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
