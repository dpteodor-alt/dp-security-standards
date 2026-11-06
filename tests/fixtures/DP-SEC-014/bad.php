<?php
/**
 * DP-SEC-014 bad: uploads without WordPress type checks; SVG allowed.
 *
 * Fixture for tests/run.sh. Lines that must produce a finding end with
 * "// expect: <rule id or PHPCS sniff code>". A good.php must produce no finding at all.
 *
 * @package DP_Security_Standards
 */

/**
 * Handles a CV and a photo upload.
 */
function dp_handle_cv_upload() {
	check_ajax_referer( 'dp_cv' );
	if ( ! current_user_can( 'upload_files' ) || ! isset( $_FILES['cv'], $_FILES['photo']['tmp_name'] ) ) {
		wp_die();
	}
	require_once ABSPATH . 'wp-admin/includes/file.php';
	$dir = wp_upload_dir()['basedir'];
	wp_handle_upload( $_FILES['cv'], array( 'test_form' => false, 'test_type' => false ) ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- fixture focuses on DP-SEC-014. expect: dp-sec-014
	move_uploaded_file( $_FILES['photo']['tmp_name'], $dir . '/photo.jpg' ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- fixture focuses on DP-SEC-014. expect: dp-sec-014
}

add_filter(
	'upload_mimes',
	function ( $mimes ) {
		$mimes['svg'] = 'image/svg+xml'; // expect: dp-sec-014-mimes
		return $mimes;
	}
);
