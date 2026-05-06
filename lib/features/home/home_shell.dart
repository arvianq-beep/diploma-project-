import 'package:diploma_application_ml/features/analysis/analysis_screen.dart';
import 'package:diploma_application_ml/features/dashboard/dashboard_screen.dart';
import 'package:diploma_application_ml/features/home/app_controller.dart';
import 'package:diploma_application_ml/features/realtime/realtime_monitor_screen.dart';
import 'package:diploma_application_ml/features/reports/reports_screen.dart';
import 'package:diploma_application_ml/features/settings/settings_screen.dart';
import 'package:diploma_application_ml/shared/widgets/threat_toast.dart';
import 'package:flutter/material.dart';

class HomeShell extends StatelessWidget {
  const HomeShell({super.key, required this.controller});

  final AppController controller;

  @override
  Widget build(BuildContext context) {
    // ThreatToastOverlay is outside AnimatedBuilder so its toast state
    // is never discarded when the controller calls notifyListeners().
    return ThreatToastOverlay(
      stream: controller.threatAlerts,
      child: AnimatedBuilder(
        animation: controller,
        builder: (context, _) {
          if (controller.initializing) {
            return const Scaffold(
              body: Center(child: CircularProgressIndicator()),
            );
          }

          final screens = [
            DashboardScreen(controller: controller),
            AnalysisScreen(controller: controller),
            RealtimeMonitorScreen(controller: controller),
            ReportsScreen(controller: controller),
            SettingsScreen(controller: controller),
          ];

          return Scaffold(
            body: SafeArea(child: screens[controller.tabIndex]),
            bottomNavigationBar: NavigationBar(
              selectedIndex: controller.tabIndex,
              onDestinationSelected: controller.setTabIndex,
              destinations: [
                const NavigationDestination(
                  icon: Icon(Icons.dashboard_outlined),
                  label: 'Dashboard',
                ),
                const NavigationDestination(
                  icon: Icon(Icons.analytics_outlined),
                  label: 'Analysis',
                ),
                NavigationDestination(
                  icon: controller.realtimeRunning
                      ? const Icon(Icons.radar, color: Colors.green)
                      : const Icon(Icons.radar_outlined),
                  label: 'Monitor',
                ),
                const NavigationDestination(
                  icon: Icon(Icons.article_outlined),
                  label: 'Reports',
                ),
                const NavigationDestination(
                  icon: Icon(Icons.settings_outlined),
                  label: 'About',
                ),
              ],
            ),
          );
        },
      ),
    );
  }
}
