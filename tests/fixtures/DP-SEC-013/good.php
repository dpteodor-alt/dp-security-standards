<?php
/**
 * DP-SEC-013 good: private meta stays out of REST; the browser gets no secret.
 *
 * Fixture for tests/run.sh. Lines that must produce a finding end with
 * "// expect: <rule id or PHPCS sniff code>". A good.php must produce no finding at all.
 *
 * @package DP_Security_Standards
 */

add_action(
	'init',
	function () {
		register_post_meta(
			'dp_lead',
			'dp_lead_email',
			array(
				'type'          => 'string',
				'single'        => true,
				'show_in_rest'  => false,
				'auth_callback' => function () {
					return current_user_can( 'edit_others_posts' );
				},
			)
		);
		register_post_meta(
			'dp_event',
			'dp_event_venue',
			array(
				'single' => true,
				'type'   => 'string',
			)
		);
	}
);

add_action(
	'wp_enqueue_scripts',
	function () {
		wp_localize_script(
			'dp-map',
			'dpMap',
			array(
				'restUrl' => esc_url_raw( rest_url( 'dp/v1/map' ) ),
				'nonce'   => wp_create_nonce( 'wp_rest' ),
			)
		);
	}
);
