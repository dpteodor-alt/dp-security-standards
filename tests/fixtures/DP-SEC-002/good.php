<?php
/**
 * DP-SEC-002 good: nonce plus capability with the object ID.
 *
 * Fixture for tests/run.sh. Lines that must produce a finding end with
 * "// expect: <rule id or PHPCS sniff code>". A good.php must produce no finding at all.
 *
 * @package DP_Security_Standards
 */

/**
 * Events controller.
 */
class DP_Events_Controller {

	/**
	 * Registers routes.
	 */
	public function register() {
		register_rest_route(
			'dp/v1',
			'/events',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'create' ),
				'permission_callback' => array( $this, 'create_permissions_check' ),
			)
		);
		register_rest_route(
			'dp/v1',
			'/events/(?P<id>\d+)',
			array(
				'methods'             => 'DELETE',
				'callback'            => array( $this, 'delete' ),
				'permission_callback' => fn( $request ) => current_user_can( 'delete_post', (int) $request['id'] ),
			)
		);
	}

	/**
	 * Nonce for intent, capability for identity.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return bool
	 */
	public function create_permissions_check( $request ) {
		return false !== wp_verify_nonce( $request->get_header( 'X-DP-Nonce' ), 'dp-events' )
			&& current_user_can( 'publish_posts' );
	}
}
