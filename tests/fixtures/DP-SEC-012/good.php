<?php
/**
 * DP-SEC-012 good: isset, unslash, sanitize.
 *
 * Fixture for tests/run.sh. Lines that must produce a finding end with
 * "// expect: <rule id or PHPCS sniff code>". A good.php must produce no finding at all.
 *
 * @package DP_Security_Standards
 */

/**
 * Stores the last search term.
 */
function dp_handle_search() {
	check_admin_referer( 'dp_search' );
	if ( ! current_user_can( 'edit_posts' ) ) {
		return;
	}
	$term = isset( $_POST['term'] ) ? sanitize_text_field( wp_unslash( $_POST['term'] ) ) : '';
	$page = isset( $_POST['page'] ) ? absint( $_POST['page'] ) : 1;
	update_option( 'dp_last_search', array( $term, $page ) );
}
