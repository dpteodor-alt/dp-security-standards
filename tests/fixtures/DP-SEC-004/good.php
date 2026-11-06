<?php
/**
 * DP-SEC-004 good: allowlisted scope; signed round-trip state.
 *
 * Fixture for tests/run.sh. Lines that must produce a finding end with
 * "// expect: <rule id or PHPCS sniff code>". A good.php must produce no finding at all.
 *
 * @package DP_Security_Standards
 */

/**
 * Load more: post type from an allowlist, status fixed on the server.
 *
 * @param WP_REST_Request $request Request.
 * @return WP_Query
 */
function dp_load_more( WP_REST_Request $request ) {
	$allowed_types = array( 'post', 'dp_event' );
	$type          = (string) $request->get_param( 'type' );
	$args          = array(
		'post_type'   => in_array( $type, $allowed_types, true ) ? $type : 'post',
		'post_status' => 'publish',
		'paged'       => absint( $request->get_param( 'page' ) ),
	);
	return new WP_Query( $args );
}

/**
 * Query vars from the browser are used only with a valid server signature,
 * and the scope is constrained again afterwards.
 *
 * @param WP_REST_Request $request Request.
 * @return WP_Query
 */
function dp_query_result( WP_REST_Request $request ) {
	$vars      = json_decode( (string) $request->get_param( 'queryVars' ), true );
	$signature = (string) $request->get_param( 'signature' );
	$defaults  = dp_saved_query_vars( absint( $request->get_param( 'element' ) ) );
	if ( ! is_array( $vars ) || ! dp_verify_state( $vars, 'dp-load-more', $signature ) ) {
		$vars = $defaults;
	}
	$vars['post_type']   = $defaults['post_type'];
	$vars['post_status'] = 'publish';
	return new WP_Query( $vars );
}

/**
 * Search: the term comes from the request, the scope does not.
 *
 * @param WP_REST_Request $request Request.
 * @return WP_Query
 */
function dp_search( WP_REST_Request $request ) {
	$args              = array(
		'post_type'   => 'post',
		'post_status' => 'publish',
	);
	$args['s']         = sanitize_text_field( (string) $request->get_param( 's' ) );
	$args['post_type'] = 'post';
	return new WP_Query( $args );
}

/**
 * Guard style allowlist.
 *
 * @param WP_REST_Request $request Request.
 * @return WP_Query|null
 */
function dp_by_type( WP_REST_Request $request ) {
	$type = sanitize_key( (string) $request->get_param( 'type' ) );
	if ( ! in_array( $type, array( 'post', 'dp_event' ), true ) ) {
		return null;
	}
	return new WP_Query(
		array(
			'post_type'   => $type,
			'post_status' => 'publish',
		)
	);
}
