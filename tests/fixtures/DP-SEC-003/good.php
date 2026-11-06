<?php
/**
 * DP-SEC-003 good: logged-in handler with nonce and capability.
 *
 * Fixture for tests/run.sh. Lines that must produce a finding end with
 * "// expect: <rule id or PHPCS sniff code>". A good.php must produce no finding at all.
 *
 * @package DP_Security_Standards
 */

add_action( 'wp_ajax_dp_save_lead', 'dp_save_lead' );

/**
 * Saves a lead. Logged-in editors only.
 */
function dp_save_lead() {
	check_ajax_referer( 'dp_save_lead' );
	if ( ! current_user_can( 'edit_posts' ) ) {
		wp_send_json_error( null, 403 );
	}
	$name = isset( $_POST['name'] ) ? sanitize_text_field( wp_unslash( $_POST['name'] ) ) : '';
	update_option( 'dp_last_lead', $name );
	wp_send_json_success();
}
