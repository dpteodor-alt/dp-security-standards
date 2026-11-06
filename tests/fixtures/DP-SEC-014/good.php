<?php
/**
 * DP-SEC-014 good: wp_handle_upload with the default type test and a narrow MIME list.
 *
 * Fixture for tests/run.sh. Lines that must produce a finding end with
 * "// expect: <rule id or PHPCS sniff code>". A good.php must produce no finding at all.
 *
 * @package DP_Security_Standards
 */

/**
 * Handles a CV upload (PDF only).
 */
function dp_handle_cv_upload() {
	check_ajax_referer( 'dp_cv' );
	if ( ! current_user_can( 'upload_files' ) || ! isset( $_FILES['cv'] ) ) {
		wp_die();
	}
	require_once ABSPATH . 'wp-admin/includes/file.php';
	// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- wp_handle_upload() validates the file array, name and type.
	$upload = wp_handle_upload(
		$_FILES['cv'],
		array(
			'test_form' => false,
			'mimes'     => array( 'pdf' => 'application/pdf' ),
		)
	);
	wp_send_json_success( isset( $upload['url'] ) ? esc_url_raw( $upload['url'] ) : '' );
}
