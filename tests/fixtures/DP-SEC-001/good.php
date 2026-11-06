<?php
/**
 * DP-SEC-001 good: every route states who may call it.
 *
 * Fixture for tests/run.sh. Lines that must produce a finding end with
 * "// expect: <rule id or PHPCS sniff code>". A good.php must produce no finding at all.
 *
 * @package DP_Security_Standards
 */

add_action( 'rest_api_init', 'dp_register_routes' );

/**
 * Registers the plugin routes.
 */
function dp_register_routes() {
	register_rest_route(
		'dp/v1',
		'/settings',
		array(
			'methods'             => WP_REST_Server::CREATABLE,
			'callback'            => 'dp_save_settings',
			'permission_callback' => static function () {
				return current_user_can( 'manage_options' );
			},
		)
	);
	register_rest_route(
		'dp/v1',
		'/items/(?P<id>\d+)',
		array(
			'methods'             => WP_REST_Server::DELETABLE,
			'callback'            => 'dp_delete_item',
			'permission_callback' => 'dp_can_delete_item',
			'args'                => array(
				'id' => array( 'sanitize_callback' => 'absint' ),
			),
		)
	);
}

/**
 * Capability check with the object ID.
 *
 * @param WP_REST_Request $request Request.
 * @return bool
 */
function dp_can_delete_item( WP_REST_Request $request ) {
	return current_user_can( 'delete_post', (int) $request['id'] );
}
