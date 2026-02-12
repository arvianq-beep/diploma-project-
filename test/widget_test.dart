import 'package:flutter_test/flutter_test.dart';
import 'package:diploma_application_ml/main.dart';

void main() {
  testWidgets('App boots', (WidgetTester tester) async {
    await tester.pumpWidget(const DiplomaApp());
    await tester.pumpAndSettle();

    // Проверяем, что приложение запустилось и показало главную страницу
    expect(find.text('Secure Decision-Making IDS'), findsOneWidget);
    expect(find.text('Dashboard'), findsOneWidget);
    expect(find.text('Alerts'), findsOneWidget);
    expect(find.text('Reports'), findsOneWidget);
  });
}
