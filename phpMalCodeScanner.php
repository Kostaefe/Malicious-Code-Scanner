<?php
/*
 * Plugin Name: php Malicious Code Scanner
 * Plugin URI: http://www.mikestowe.com/phpmalcode
 * Description: The php Malicious Code Scanner checks all files for one of the most common malicious code attacks, the eval( base64_decode() ) attack...
 * Version: 1.3 beta
 * Author: Michael Stowe
 * Author URI: http://www.mikestowe.com
 * Credits: Based on the idea of Er. Rochak Chauhan (http://www.rochakchauhan.com/), rewritten for use with a cron job
 * License: GPL-2
 */

/**
 * Set to your email:
 *
 * @var string
 */
define('SEND_EMAIL_ALERTS_TO', 'youremail@example.com');

/**
 * Scans recursively all directories for eval and base64 content
 *
 * @author Michael Stowe
 */
class phpMalCodeScan {

	/**
	 * Infected filenames
	 *
	 * @var array
	 */
	public $infected_files = array();

	/**
	 * The Scanned Files
	 *
	 * @var array
	 */
	private $scanned_files = array();

	/**
	 * Scans recursively all directories for eval and base64 content.
	 * Send E-Mail Report.
	 */
	function __construct() {
		try {
			// First Scan
			$this->scan(dirname(__FILE__));
			// Than send e-mail
			$this->sendalert();
		} catch (Exception $e) {
			// On Exception send Mail too
			$this->sendalert('
' . $e->getMessage());
		}
	}

	/**
	 * Scans recursively all directories for eval and base64 content.
	 *
	 * @param string $dir
	 *        	Path
	 * @throws Exception
	 */
	public function scan($dir) {
		$this->scanned_files [] = $dir;
		$files = scandir($dir);

		if (!is_array($files)) {
			throw new Exception('Unable to scan directory ' . $dir . '.  Please make sure proper permissions have been set.');
		}

		// Loop all directorys
		foreach ($files as $file) {
			if (is_file($dir . '/' . $file) && !in_array($dir . '/' . $file, $this->scanned_files)) {
				$this->check(file_get_contents($dir . '/' . $file), $dir . '/' . $file);
			} elseif (is_dir($dir . '/' . $file) && substr($file, 0, 1) != '.') {
				$this->scan($dir . '/' . $file);
			}
		}
	}

	/**
	 * Check files for eval and base64 content.
	 * Save infected filenames in Member Variable
	 *
	 * @param string $contents
	 * @param string $file
	 *        	filepath
	 */
	public function check($contents, $file) {
		$this->scanned_files [] = $file;
		if (preg_match('/(?<![a-z0-9_])eval\((base64|eval|\$_|\$\$|\$[A-Za-z_0-9\{]*(\(|\{|\[))/i', $contents)) {
			$this->infected_files [] = $file;
		}
	}

	/**
	 * Send an E-mail
	 *
	 * @param string $onExceptionMessage
	 */
	public function sendalert($onExceptionMessage = '') {
		$message = '== Malicious Scan Report == 
';
		$message .= 'Scanned Files: ' . count($this->scanned_files) . ' 
';

		if (count($this->infected_files) != 0) {
			$message .= "== MALICIOUS CODE FOUND == 
";
			$message .= "The following files appear to be infected: 
";
			foreach ($this->infected_files as $inf) {
				$message .= "  -  $inf 
";
			}
		} else {
			$message .= 'No Malicious Code Found!';
		}

		$from = 'FROM: Code Scanner <noreply@' . gethostname() . '>';
		// Send E-Mail
		mail(SEND_EMAIL_ALERTS_TO, 'Malicious Report', $message . $onExceptionMessage, $from);
	}

}

ini_set('memory_limit', '-1'); // # Avoid memory errors (i.e in foreachloop)
new phpMalCodeScan();
?>