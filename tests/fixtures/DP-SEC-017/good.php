<?php
/**
 * DP-SEC-017 good: is_admin() for context only; current_user_can() for authorization.
 *
 * Fixture for tests/run.sh. Lines that must produce a finding end with
 * "// expect: <rule id or PHPCS sniff code>". A good.php must produce no finding at all.
 *
 * @package DP_Security_Standards
 */

register_rest_route(
	'dp/v1',
	'/cache',
	array(
		'methods'             => 'POST',
		'callback'            => 'dp_flush_cache',
		'permission_callback' => function () {
			return current_user_can( 'manage_options' );
		},
	)
);

/**
 * Saves the layout setting.
 */
function dp_maybe_save_layout() {
	if ( ! is_admin() || ! isset( $_POST['dp_layout'] ) ) {
		return;
	}
	check_admin_referer( 'dp_layout' );
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}
	update_option( 'dp_layout', sanitize_key( wp_unslash( $_POST['dp_layout'] ) ) );
}
add_action( 'admin_init', 'dp_maybe_save_layout' );

/**
 * Context plus capability.
 *
 * @return bool
 */
function dp_purge_permissions_check() {
	return is_admin() && current_user_can( 'manage_options' );
}
