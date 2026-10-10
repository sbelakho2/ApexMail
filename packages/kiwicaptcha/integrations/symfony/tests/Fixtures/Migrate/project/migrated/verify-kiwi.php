<?php
/**
 * The migrated verify call: the same provider request shape, pointed
 * at the kiwi deployment's siteverify endpoint.
 */

function acme_verify_with_kiwi($token) {
    $response = wp_remote_post('https://kiwi.internal/kiwi-captcha/siteverify', [
        'body' => [
            'secret' => ACME_KIWI_SITEVERIFY_SECRET,
            'response' => $token,
            'remoteip' => isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '',
        ],
    ]);

    return !is_wp_error($response);
}
