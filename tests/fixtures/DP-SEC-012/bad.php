<?php
/**
 * DP-SEC-012 bad: input used without validation or sanitization.
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
	$term = $_POST['term']; // expect: WordPress.Security.ValidatedSanitizedInput.InputNotValidated, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash
	update_option( 'dp_last_search', $term );
}
