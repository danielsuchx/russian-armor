// Fixed native IPC dispatch; generated from registered commands.
use serde_json::Value;
pub async fn dispatch(app: tauri::AppHandle, command: &str, args: Value) -> Result<Value, Value> {
    match command {
        "get_coverage_snapshot" | "recheck_coverage" | "reapply_browser_policies_cmd" | "relaunch_browsers_with_pac_cmd" => crate::commands::coverage::native_call(command, args, app).await,
        "get_cowork_guard_status" | "install_or_repair_cowork_guard" => crate::commands::autostart::native_call(command, args, app).await,
        "clean_app_cache" | "scan_claude_data_cmd" | "export_claude_data_cmd" | "list_claude_profiles_cmd" | "create_claude_profile_cmd" | "switch_claude_profile_cmd" | "delete_claude_profile_cmd" | "bind_ip_to_claude_profile_cmd" | "bind_upstream_to_claude_profile_cmd" | "bind_route_to_claude_profile" | "safe_logout_claude_cmd" | "clear_ip_change_cooldown_cmd" => crate::commands::claude::native_call(command, args, app).await,
        "take_pending_deep_link" => crate::commands::deeplink::native_call(command, args, app).await,
        "get_custom_ai_domains_cmd" | "add_custom_ai_domain_cmd" | "remove_custom_ai_domain_cmd" => crate::commands::domains::native_call(command, args, app).await,
        "check_payment_bin" | "set_warmup_timer" => crate::commands::payment::native_call(command, args, app).await,
        "list_routes" | "add_route" | "remove_route" | "set_route_enabled" | "bind_provider_route" | "set_default_route" | "test_route" => crate::commands::routes::native_call(command, args, app).await,
        "run_vpn_crash_test_step" | "trigger_crash_test_drop" | "reset_crash_test_drop" => crate::commands::crash_test::native_call(command, args, app).await,
        "set_upstream_proxy" | "toggle_upstream_proxy" | "clear_upstream_proxy" => crate::commands::upstream::native_call(command, args, app).await,
        "restart_app_with_gateway" => crate::commands::restart_app::native_call(command, args, app).await,
        "resolve_interception" | "simulate_interception" | "take_pending_alert" | "get_interception_behavior_cmd" | "set_interception_behavior_cmd" | "get_popup_position_cmd" | "set_popup_position_cmd" | "toggle_network_killswitch_cmd" | "get_network_killswitch_status_cmd" | "pause_until_network_change_cmd" | "set_guard_pause_mode_cmd" | "get_guard_pause_status_cmd" => crate::commands::interception::native_call(command, args, app).await,
        "get_state" | "get_startup_state" | "audit_connection" | "pin_current_ip" | "unpin_ip" | "get_pinned_ips" | "get_onboarding_v2_2_done" | "set_onboarding_v2_2_done" | "get_hide_ip_mode" | "set_hide_ip_mode" | "toggle_strict_pinning" | "allow_provider_session" | "unblock_provider_cmd" | "verify_and_unblock_provider" | "set_provider_monitoring" | "remove_trusted_exception" | "clear_trusted_exceptions" | "get_gateway_stats" | "get_split_tunnel_mode" | "set_split_tunnel_mode" => crate::commands::audit::native_call(command, args, app).await,
        "toggle_sysproxy" | "toggle_sysproxy_privileged" | "enable_cli_protection" | "disable_cli_protection" | "check_cli_protection_status" | "sync_ai_agents_timezone" | "sync_os_timezone_cmd" | "restore_os_timezone_cmd" | "get_os_timezone_sync_status_cmd" | "get_cli_settings" | "set_cli_mode" | "set_sync_ai_tz_enabled" | "open_os_datetime_settings_cmd" | "open_os_network_settings_cmd" | "get_sysproxy_status" | "get_error_diagnostics" | "export_diagnostic_bundle_cmd" | "preview_protection_changes_cmd" | "force_clean_os_proxy_cmd" => crate::commands::sysproxy::native_call(command, args, app).await,
        _ => Err(serde_json::json!({"message":"Command is owned by the native application or unavailable"})),
    }
}
