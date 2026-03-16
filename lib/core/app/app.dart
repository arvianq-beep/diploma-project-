import 'package:diploma_application_ml/core/theme/app_theme.dart';
import 'package:diploma_application_ml/data/repositories/ids_repository.dart';
import 'package:diploma_application_ml/features/home/app_controller.dart';
import 'package:diploma_application_ml/features/home/home_shell.dart';
import 'package:flutter/material.dart';

class DiplomaApp extends StatefulWidget {
  const DiplomaApp({super.key});

  @override
  State<DiplomaApp> createState() => _DiplomaAppState();
}

class _DiplomaAppState extends State<DiplomaApp> {
  late final AppController controller;

  @override
  void initState() {
    super.initState();
    controller = AppController(repository: IdsRepository())..initialize();
  }

  @override
  void dispose() {
    controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      title: 'AI-driven IDS with Verification Layer',
      theme: buildAppTheme(),
      home: HomeShell(controller: controller),
    );
  }
}
