import 'package:intl/intl.dart';

final DateFormat _dateTimeFormat = DateFormat('MMM d, yyyy  HH:mm');
final DateFormat _shortDateFormat = DateFormat('MMM d');

String formatDateTime(DateTime value) =>
    _dateTimeFormat.format(value.toLocal());

String formatShortDate(DateTime value) =>
    _shortDateFormat.format(value.toLocal());

String formatPercent(double value) => '${(value * 100).toStringAsFixed(1)}%';

String formatRisk(double value) => value.toStringAsFixed(2);
