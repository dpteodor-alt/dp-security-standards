<?php
/**
 * DP-SEC-015 bad: a nonce but no capability before the write.
 *
 * Fixture for tests/run.sh. Lines that must produce a finding end with
 * "// expect: <rule id or PHPCS sniff code>". A good.php must produce no finding at all.
 *
 * @package DP_Security_Standards
 */

/**
 * Deletes a lead. Any logged-in user can get the nonce.
 */
function dp_ajax_delete_lead() {
	check_ajax_referer( 'dp_leads' );
	$lead_id = isset( $_POST['lead_id'] ) ? absint( $_POST['lead_id'] ) : 0;
	wp_delete_post( $lead_id, true ); // expect: dp-sec-015
	wp_send_json_success();
}
add_action( 'wp_ajax_dp_delete_lead', 'dp_ajax_delete_lead' );

add_action(
	'wp_ajax_dp_reset',
	function () {
		check_ajax_referer( 'dp_reset' );
		delete_option( 'dp_settings' ); // expect: dp-sec-015
		wp_send_json_success();
	}
);
