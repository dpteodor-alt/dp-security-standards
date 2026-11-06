<?php
/**
 * DP-SEC-004 bad: the client chooses the query scope.
 *
 * Fixture for tests/run.sh. Lines that must produce a finding end with
 * "// expect: <rule id or PHPCS sniff code>". A good.php must produce no finding at all.
 *
 * @package DP_Security_Standards
 */

/**
 * Load more: post type and status come from the request.
 *
 * @param WP_REST_Request $request Request.
 * @return WP_Query
 */
function dp_load_more( WP_REST_Request $request ) {
	$args = array(
		'post_type'   => sanitize_key( $request->get_param( 'type' ) ), // expect: dp-sec-004
		'post_status' => 'publish',
		'paged'       => absint( $request->get_param( 'page' ) ),
	);
	$args['post_status'] = sanitize_text_field( $request['status'] ); // expect: dp-sec-004
	$args['post__in']    = wp_parse_id_list( $request->get_param( 'ids' ) ); // expect: dp-sec-004-ids
	return new WP_Query( $args );
}

/**
 * The Bricks CVE-2026-118804 pattern: query vars restored from the browser.
 *
 * @param WP_REST_Request $request Request.
 * @return WP_Query
 */
function dp_query_result( WP_REST_Request $request ) {
	$vars = json_decode( $request->get_param( 'queryVars' ), true );
	return new WP_Query( wp_parse_args( $vars, array( 'post_type' => 'post' ) ) ); // expect: dp-sec-004-whole-args
}

/**
 * Archive filter: the status comes from the query string.
 *
 * @param WP_Query $query Query.
 */
function dp_filter_archive( $query ) {
	if ( $query->is_main_query() && isset( $_GET['status'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- fixture focuses on DP-SEC-004.
		$query->set( 'post_status', sanitize_key( wp_unslash( $_GET['status'] ) ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- fixture focuses on DP-SEC-004. expect: dp-sec-004
	}
}
add_action( 'pre_get_posts', 'dp_filter_archive' );

/**
 * Whole query passed as one request field.
 *
 * @param WP_REST_Request $request Request.
 * @return WP_Query
 */
function dp_query_field( WP_REST_Request $request ) {
	return new WP_Query( $request->get_param( 'query' ) ); // expect: dp-sec-004-whole-args
}
