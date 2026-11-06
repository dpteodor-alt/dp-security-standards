<?php
/**
 * DP-SEC-017 bad: is_admin() used as authorization.
 *
 * Fixture for tests/run.sh. Lines that must produce a finding end with
 * "// expect: <rule id or PHPCS sniff code>". A good.php must produce no finding at all.
 *
 * @package DP_Security_Standards
 */

register_rest_route( 'dp/v1', '/cache', array( 'methods' => 'POST', 'callback' => 'dp_flush_cache', 'permission_callback' => function () { return is_admin(); } ) ); // expect: dp-sec-017

/**
 * Saves the layout setting for "admins".
 */
function dp_maybe_save_layout() {
	if ( ! is_admin() ) { // expect: dp-sec-017
		return;
	}
	check_admin_referer( 'dp_layout' );
	if ( isset( $_POST['dp_layout'] ) ) {
		update_option( 'dp_layout', sanitize_key( wp_unslash( $_POST['dp_layout'] ) ) );
	}
}
add_action( 'init', 'dp_maybe_save_layout' );

register_rest_route( 'dp/v1', '/purge', array( 'methods' => 'POST', 'callback' => 'dp_purge', 'permission_callback' => 'is_admin' ) ); // expect: dp-sec-017

add_action(
	'wp_ajax_dp_toggle',
	function () {
		check_ajax_referer( 'dp_toggle' );
		if ( is_admin() && isset( $_POST['on'] ) ) { // expect: dp-sec-017
			update_option( 'dp_toggle', absint( $_POST['on'] ) ); // expect: dp-sec-015
		}
	}
);
