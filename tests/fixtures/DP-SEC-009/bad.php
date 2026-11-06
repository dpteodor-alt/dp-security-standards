<?php
/**
 * DP-SEC-009 bad: SQL built by string interpolation.
 *
 * Fixture for tests/run.sh. Lines that must produce a finding end with
 * "// expect: <rule id or PHPCS sniff code>". A good.php must produce no finding at all.
 *
 * @package DP_Security_Standards
 */

/**
 * Visits by referrer.
 *
 * @param string $referrer Referrer.
 * @return array
 */
function dp_get_visits( $referrer ) {
	global $wpdb;
	return $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}dp_referrers WHERE referrer = '$referrer'" ); // expect: WordPress.DB.PreparedSQL.InterpolatedNotPrepared
}

/**
 * Visits sorted by a column name from the caller.
 *
 * @param string $orderby Column.
 * @return array
 */
function dp_get_sorted( $orderby ) {
	global $wpdb;
	$table = $wpdb->prefix . 'dp_referrers';
	return $wpdb->get_results( 'SELECT * FROM ' . $table . ' ORDER BY ' . $orderby ); // expect: WordPress.DB.PreparedSQL.NotPrepared
}
