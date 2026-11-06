<?php
/**
 * DP-SEC-016 bad: the request chooses option names, meta keys and roles.
 *
 * Fixture for tests/run.sh. Lines that must produce a finding end with
 * "// expect: <rule id or PHPCS sniff code>". A good.php must produce no finding at all.
 *
 * @package DP_Security_Standards
 */

/**
 * Saves any option the client names.
 */
function dp_ajax_save_option() {
	check_ajax_referer( 'dp_options' );
	if ( ! current_user_can( 'edit_posts' ) ) {
		wp_die();
	}
	$name  = isset( $_POST['name'] ) ? sanitize_key( wp_unslash( $_POST['name'] ) ) : '';
	$value = isset( $_POST['value'] ) ? sanitize_text_field( wp_unslash( $_POST['value'] ) ) : '';
	update_option( $name, $value ); // expect: dp-sec-016
}

/**
 * Updates profile fields and role from the request.
 *
 * @param WP_REST_Request $request Request.
 */
function dp_update_profile( WP_REST_Request $request ) {
	foreach ( (array) $request->get_param( 'fields' ) as $key => $value ) {
		update_user_meta( get_current_user_id(), sanitize_key( $key ), sanitize_text_field( $value ) ); // expect: dp-sec-016
	}
	wp_update_user( array( 'ID' => get_current_user_id(), 'role' => sanitize_key( $request->get_param( 'role' ) ) ) ); // expect: dp-sec-016
}

/**
 * Registration that trusts the request.
 */
function dp_ajax_register() {
	check_ajax_referer( 'dp_register' );
	$userdata         = array( 'user_login' => 'x' );
	$userdata['role'] = isset( $_POST['role'] ) ? sanitize_key( wp_unslash( $_POST['role'] ) ) : 'subscriber'; // expect: dp-sec-016
	wp_insert_user( $userdata ); // expect: dp-sec-016-userdata
	wp_update_user( wp_unslash( $_POST ) ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- fixture focuses on DP-SEC-016. expect: dp-sec-016-userdata
}
