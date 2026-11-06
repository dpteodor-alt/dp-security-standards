<?php
/**
 * DP-SEC-007 good: fixed host; the client only supplies a parameter.
 *
 * Fixture for tests/run.sh. Lines that must produce a finding end with
 * "// expect: <rule id or PHPCS sniff code>". A good.php must produce no finding at all.
 *
 * @package DP_Security_Standards
 */

/**
 * Fetches oEmbed data from a fixed host.
 *
 * @param WP_REST_Request $request Request.
 * @return array|null
 */
function dp_fetch_oembed( WP_REST_Request $request ) {
	$video_id = preg_replace( '/[^A-Za-z0-9_-]/', '', (string) $request->get_param( 'id' ) );
	$url      = add_query_arg(
		array(
			'url'    => 'https://www.youtube.com/watch?v=' . $video_id,
			'format' => 'json',
		),
		'https://www.youtube.com/oembed'
	);
	$response = wp_remote_get( $url );
	return json_decode( wp_remote_retrieve_body( $response ), true );
}

/**
 * Verifies an API key against the provider's fixed endpoint.
 *
 * @param string $endpoint Endpoint from saved settings (validated on save).
 * @return bool
 */
function dp_check_saved_endpoint( $endpoint ) {
	$response = wp_safe_remote_get( $endpoint );
	return 200 === wp_remote_retrieve_response_code( $response );
}
