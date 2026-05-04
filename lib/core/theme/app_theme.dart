import 'package:flutter/material.dart';

ThemeData buildAppTheme() {
  const base = Color(0xFF0B1220);
  const surface = Color(0xFFF6F8FC);
  const primary = Color(0xFF124170);
  const accent = Color(0xFF2A7ABF);
  const threat = Color(0xFFB42318);
  const warning = Color(0xFFB54708);
  const safe = Color(0xFF027A48);

  final scheme =
      ColorScheme.fromSeed(
        seedColor: primary,
        brightness: Brightness.light,
        surface: Colors.white,
      ).copyWith(
        primary: primary,
        secondary: accent,
        error: threat,
        tertiary: warning,
      );

  return ThemeData(
    useMaterial3: true,
    colorScheme: scheme,
    scaffoldBackgroundColor: surface,
    appBarTheme: const AppBarTheme(
      backgroundColor: Colors.transparent,
      foregroundColor: base,
      elevation: 0,
      centerTitle: false,
    ),
    cardTheme: CardThemeData(
      color: Colors.white,
      elevation: 0,
      margin: EdgeInsets.zero,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(24),
        side: BorderSide(color: Colors.blueGrey.withValues(alpha: 0.08)),
      ),
    ),
    chipTheme: ChipThemeData(
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(999)),
      side: BorderSide(color: accent.withValues(alpha: 0.18)),
      selectedColor: accent.withValues(alpha: 0.12),
      backgroundColor: const Color(0xFFEFF4FB),
      // Explicit color so Material 3 doesn't compute it as grey on
      // light surfaces.
      labelStyle: const TextStyle(
        fontWeight: FontWeight.w600,
        color: Color(0xFF0B1220),
      ),
    ),
    textTheme: const TextTheme(
      headlineMedium: TextStyle(
        fontSize: 28,
        fontWeight: FontWeight.w700,
        color: base,
      ),
      headlineSmall: TextStyle(
        fontSize: 22,
        fontWeight: FontWeight.w700,
        color: base,
      ),
      titleLarge: TextStyle(
        fontSize: 18,
        fontWeight: FontWeight.w700,
        color: base,
      ),
      titleMedium: TextStyle(
        fontSize: 15,
        fontWeight: FontWeight.w700,
        color: base,
      ),
      bodyLarge: TextStyle(fontSize: 15, color: base),
      bodyMedium: TextStyle(fontSize: 13, color: Color(0xFF344054)),
    ),
    filledButtonTheme: FilledButtonThemeData(
      style: FilledButton.styleFrom(
        backgroundColor: primary,
        foregroundColor: Colors.white,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
        padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 16),
      ),
    ),
    outlinedButtonTheme: OutlinedButtonThemeData(
      style: OutlinedButton.styleFrom(
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
        padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 16),
      ),
    ),
    inputDecorationTheme: InputDecorationTheme(
      filled: true,
      fillColor: const Color(0xFFF8FAFC),
      border: OutlineInputBorder(
        borderRadius: BorderRadius.circular(16),
        borderSide: BorderSide(color: Colors.blueGrey.withValues(alpha: 0.18)),
      ),
      enabledBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(16),
        borderSide: BorderSide(color: Colors.blueGrey.withValues(alpha: 0.18)),
      ),
      focusedBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(16),
        borderSide: const BorderSide(color: accent, width: 1.4),
      ),
    ),
    extensions: const <ThemeExtension<dynamic>>[
      StatusPalette(benign: safe, verifiedThreat: threat, suspicious: warning),
    ],
  );
}

@immutable
class StatusPalette extends ThemeExtension<StatusPalette> {
  final Color benign;
  final Color verifiedThreat;
  final Color suspicious;

  const StatusPalette({
    required this.benign,
    required this.verifiedThreat,
    required this.suspicious,
  });

  @override
  StatusPalette copyWith({
    Color? benign,
    Color? verifiedThreat,
    Color? suspicious,
  }) {
    return StatusPalette(
      benign: benign ?? this.benign,
      verifiedThreat: verifiedThreat ?? this.verifiedThreat,
      suspicious: suspicious ?? this.suspicious,
    );
  }

  @override
  StatusPalette lerp(ThemeExtension<StatusPalette>? other, double t) {
    if (other is! StatusPalette) {
      return this;
    }

    return StatusPalette(
      benign: Color.lerp(benign, other.benign, t) ?? benign,
      verifiedThreat:
          Color.lerp(verifiedThreat, other.verifiedThreat, t) ?? verifiedThreat,
      suspicious: Color.lerp(suspicious, other.suspicious, t) ?? suspicious,
    );
  }
}
