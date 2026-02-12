import 'package:diploma_application_ml/Serives/api_service.dart';
import 'package:flutter/material.dart';

import 'package:diploma_application_ml/Features/Views/dashboard_view.dart';
import 'package:diploma_application_ml/Features/views/alerts_view.dart';
import 'package:diploma_application_ml/Features/Views/reports_view.dart';


import 'home_view_model.dart';

const String kBackendBaseUrl = 'http://127.0.0.1:5001';

class HomePage extends StatefulWidget {
  const HomePage({super.key});

  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  late final ApiService api;
  late final HomeViewModel vm;

  @override
  void initState() {
    super.initState();

    // Один общий ApiService для всего приложения
    api = const ApiService(baseUrl: kBackendBaseUrl);

    // ViewModel использует тот же ApiService
    vm = HomeViewModel(api: api);
  }

  @override
  void dispose() {
    vm.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: vm,
      builder: (context, _) {
        final pages = <Widget>[
          DashboardView(vm: vm),
          AlertsView(vm: vm),
          ReportsView(api: api),
        ];

        return Scaffold(
          appBar: AppBar(title: const Text('Secure Decision-Making IDS')),
          body: pages[vm.index],
          bottomNavigationBar: NavigationBar(
            selectedIndex: vm.index,
            onDestinationSelected: vm.setIndex,
            destinations: const [
              NavigationDestination(
                icon: Icon(Icons.dashboard_outlined),
                label: 'Dashboard',
              ),
              NavigationDestination(
                icon: Icon(Icons.notifications_outlined),
                label: 'Alerts',
              ),
              NavigationDestination(
                icon: Icon(Icons.article_outlined),
                label: 'Reports',
              ),
            ],
          ),
        );
      },
    );
  }
}
