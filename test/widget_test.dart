import 'package:diploma_application_ml/core/app/app.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  testWidgets('App boots', (WidgetTester tester) async {
    await tester.pumpWidget(const DiplomaApp());
    await tester.pumpAndSettle();

    expect(find.text('AI-driven IDS with Verification Layer'), findsOneWidget);
    expect(find.text('Dashboard'), findsOneWidget);
    expect(find.text('Analysis'), findsOneWidget);
    expect(find.text('Reports'), findsWidgets);
  });
}
