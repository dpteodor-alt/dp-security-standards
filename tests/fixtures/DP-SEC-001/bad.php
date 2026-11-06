<?php
/**
 * DP-SEC-001 bad: REST routes that anyone can call.
 *
 * Fixture for tests/run.sh. Lines that must produce a finding end with
 * "// expect: <rule id or PHPCS sniff code>". A good.php must produce no finding at all.
 *
 * @package DP_Security_Standards
 */

add_action(
	'rest_api_init',
	function () {
		register_rest_route( 'dp/v1', '/settings', array( 'methods' => 'POST', 'callback' => 'dp_save_settings', 'permission_callback' => '__return_true' ) ); // expect: dp-sec-001
		register_rest_route( 'dp/v1', '/items/(?P<id>\d+)', array( 'methods' => WP_REST_Server::DELETABLE, 'callback' => 'dp_delete_item', 'permission_callback' => fn() => true ) ); // expect: dp-sec-001
		register_rest_route( 'dp/v1', '/sync', array( 'methods' => WP_REST_Server::CREATABLE, 'callback' => 'dp_sync' ) ); // expect: dp-sec-001
		register_rest_route( 'dp/v1', '/events', array( 'methods' => 'GET', 'callback' => 'dp_list_events', 'permission_callback' => '__return_true' ) ); // expect: dp-sec-001-readonly
		register_rest_route( 'dp/v1', '/stats', array( 'callback' => 'dp_stats', 'permission_callback' => '__return_true' ) ); // expect: dp-sec-001-readonly
	}
);

/**
 * Variants found in review: double quotes after a closure, typed arrow function, empty callback.
 */
function dp_register_more_routes() {
	$ids = array_map( fn( $x ) => (int) $x, array( 1, 2 ) );
	register_rest_route( 'dp/v1', '/a', array( 'methods' => 'POST', 'callback' => 'dp_a', 'permission_callback' => "__return_true" ) ); // expect: dp-sec-001
	register_rest_route( 'dp/v1', '/b', array( 'methods' => 'PUT', 'callback' => 'dp_b', 'permission_callback' => fn(): bool => true ) ); // expect: dp-sec-001
	register_rest_route( 'dp/v1', '/c', array( 'methods' => 'POST', 'callback' => 'dp_c', 'permission_callback' => '' ) ); // expect: dp-sec-001
	return $ids;
}
