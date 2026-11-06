<?php
/**
 * DP-SEC-007 bad: server-side requests to a URL from the client.
 *
 * Fixture for tests/run.sh. Lines that must produce a finding end with
 * "// expect: <rule id or PHPCS sniff code>". A good.php must produce no finding at all.
 *
 * @package DP_Security_Standards
 */

/**
 * Fetches a link preview for any URL.
 *
 * @param WP_REST_Request $request Request.
 * @return string
 */
function dp_fetch_preview( WP_REST_Request $request ) {
	$url      = esc_url_raw( $request->get_param( 'url' ) );
	$response = wp_remote_get( $url ); // expect: dp-sec-007
	return wp_remote_retrieve_body( $response );
}

/**
 * Pings a webhook endpoint chosen in the request.
 */
function dp_ajax_check_webhook() {
	check_ajax_referer( 'dp_check' );
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die();
	}
	$endpoint = isset( $_POST['endpoint'] ) ? esc_url_raw( wp_unslash( $_POST['endpoint'] ) ) : '';
	wp_remote_post( $endpoint, array( 'body' => array( 'ping' => 1 ) ) ); // expect: dp-sec-007
}
