<?php
/**
 * DP-SEC-015 good: capability with the object ID before the write.
 *
 * Fixture for tests/run.sh. Lines that must produce a finding end with
 * "// expect: <rule id or PHPCS sniff code>". A good.php must produce no finding at all.
 *
 * @package DP_Security_Standards
 */

/**
 * Deletes a lead the current user may delete.
 */
function dp_ajax_delete_lead() {
	check_ajax_referer( 'dp_leads' );
	$lead_id = isset( $_POST['lead_id'] ) ? absint( $_POST['lead_id'] ) : 0;
	if ( ! current_user_can( 'delete_post', $lead_id ) ) {
		wp_send_json_error( null, 403 );
	}
	wp_delete_post( $lead_id, true );
	wp_send_json_success();
}
add_action( 'wp_ajax_dp_delete_lead', 'dp_ajax_delete_lead' );

add_action(
	'wp_ajax_dp_reset',
	function () {
		check_ajax_referer( 'dp_reset' );
		if ( ! user_can( wp_get_current_user(), 'manage_options' ) ) {
			wp_send_json_error( null, 403 );
		}
		delete_option( 'dp_settings' );
		wp_send_json_success();
	}
);
