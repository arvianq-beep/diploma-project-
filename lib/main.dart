import 'package:flutter/material.dart';
import 'Features/Home/Home_page.dart';

void main() {
  runApp(const DiplomaApp());
}

class DiplomaApp extends StatelessWidget {
  const DiplomaApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      title: 'Secure Decision-Making IDS',
      theme: ThemeData(useMaterial3: true),
      home: const HomePage(),
    );
  }
}
