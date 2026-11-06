<?php
/**
 * DP-SEC-008 bad: file paths built from the request.
 *
 * Fixture for tests/run.sh. Lines that must produce a finding end with
 * "// expect: <rule id or PHPCS sniff code>". A good.php must produce no finding at all.
 *
 * @package DP_Security_Standards
 */

/**
 * Includes a template named in the query string.
 */
function dp_render_template() {
	$template = isset( $_GET['tpl'] ) ? sanitize_text_field( wp_unslash( $_GET['tpl'] ) ) : 'default';
	include __DIR__ . '/templates/' . $template . '.php'; // expect: dp-sec-008
}

/**
 * Streams and deletes an export file named by the client.
 *
 * @param WP_REST_Request $request Request.
 */
function dp_download_export( WP_REST_Request $request ) {
	$file = WP_CONTENT_DIR . '/uploads/dp-exports/' . $request->get_param( 'file' );
	readfile( $file ); // expect: dp-sec-008
	unlink( $file ); // expect: dp-sec-008
}

/**
 * Template part chosen by the client.
 *
 * @param WP_REST_Request $request Request.
 */
function dp_render_part( WP_REST_Request $request ) {
	get_template_part( 'parts/card', $request->get_param( 'layout' ) ); // expect: dp-sec-008
}
