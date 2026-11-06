<?php
/**
 * DP-SEC-016 good: option names and meta keys from an allowlist; no role from the request.
 *
 * Fixture for tests/run.sh. Lines that must produce a finding end with
 * "// expect: <rule id or PHPCS sniff code>". A good.php must produce no finding at all.
 *
 * @package DP_Security_Standards
 */

/**
 * Saves one of the known options.
 */
function dp_ajax_save_option() {
	check_ajax_referer( 'dp_options' );
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die();
	}
	$allowed = array( 'dp_color', 'dp_layout' );
	$name    = isset( $_POST['name'] ) ? sanitize_key( wp_unslash( $_POST['name'] ) ) : '';
	$name    = in_array( $name, $allowed, true ) ? $name : '';
	$value   = isset( $_POST['value'] ) ? sanitize_text_field( wp_unslash( $_POST['value'] ) ) : '';
	if ( '' !== $name ) {
		update_option( $name, $value );
	}
}

/**
 * Updates the allowed profile fields only.
 *
 * @param WP_REST_Request $request Request.
 */
function dp_update_profile( WP_REST_Request $request ) {
	$fields = (array) $request->get_param( 'fields' );
	foreach ( array( 'dp_phone_public', 'dp_bio' ) as $key ) {
		if ( isset( $fields[ $key ] ) ) {
			update_user_meta( get_current_user_id(), $key, sanitize_text_field( $fields[ $key ] ) );
		}
	}
}

/**
 * Guard style allowlist for meta keys.
 *
 * @param WP_REST_Request $request Request.
 */
function dp_save_pref( WP_REST_Request $request ) {
	$key = sanitize_key( (string) $request->get_param( 'key' ) );
	if ( ! in_array( $key, array( 'dp_theme', 'dp_density' ), true ) ) {
		return;
	}
	update_user_meta( get_current_user_id(), $key, sanitize_text_field( (string) $request->get_param( 'value' ) ) );
}
