<?php
/**
 * DP-SEC-008 good: allowlisted names; realpath inside the directory.
 *
 * Fixture for tests/run.sh. Lines that must produce a finding end with
 * "// expect: <rule id or PHPCS sniff code>". A good.php must produce no finding at all.
 *
 * @package DP_Security_Standards
 */

/**
 * Includes one of the known templates.
 */
function dp_ajax_render_template() {
	check_ajax_referer( 'dp_tpl' );
	if ( ! current_user_can( 'edit_posts' ) ) {
		wp_die();
	}
	$allowed  = array( 'card', 'list', 'grid' );
	$template = isset( $_POST['tpl'] ) ? sanitize_key( wp_unslash( $_POST['tpl'] ) ) : 'card';
	$template = in_array( $template, $allowed, true ) ? $template : 'card';
	include __DIR__ . '/templates/' . $template . '.php';
}

/**
 * Streams an export file that must stay inside the export directory.
 *
 * @param WP_REST_Request $request Request.
 * @return WP_Error|null
 */
function dp_download_export( WP_REST_Request $request ) {
	$dir  = realpath( WP_CONTENT_DIR . '/uploads/dp-exports' );
	$path = realpath( $dir . '/' . basename( (string) $request->get_param( 'file' ) ) );
	if ( false === $dir || false === $path || 0 !== strpos( $path, $dir . DIRECTORY_SEPARATOR ) ) {
		return new WP_Error( 'dp_not_found', 'Not found', array( 'status' => 404 ) );
	}
	readfile( $path );
	return null;
}

/**
 * CSV import: PHP chose the temporary path, the client did not.
 */
function dp_ajax_import_csv() {
	check_ajax_referer( 'dp_import' );
	if ( ! current_user_can( 'manage_options' ) || ! isset( $_FILES['import']['tmp_name'] ) ) {
		wp_die();
	}
	$tmp    = sanitize_text_field( $_FILES['import']['tmp_name'] );
	$handle = fopen( $tmp, 'r' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- not in the security ruleset; shown for clarity.
	fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
}

/**
 * Relative path checked with validate_file().
 *
 * @param WP_REST_Request $request Request.
 * @return string
 */
function dp_read_doc( WP_REST_Request $request ) {
	$file = (string) $request->get_param( 'file' );
	if ( 0 !== validate_file( $file ) ) {
		return '';
	}
	return (string) file_get_contents( __DIR__ . '/docs/' . $file . '.md' );
}
