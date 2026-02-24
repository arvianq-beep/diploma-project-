import 'package:diploma_application_ml/Serives/api_service.dart';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';

class DatasetsView extends StatefulWidget {
  final ApiService api;
  const DatasetsView({super.key, required this.api});

  @override
  State<DatasetsView> createState() => _DatasetsViewState();
}

class _DatasetsViewState extends State<DatasetsView> {
  bool loading = false;
  List<Map<String, dynamic>> datasets = [];

  @override
  void initState() {
    super.initState();
    _refresh();
  }

  Future<void> _refresh() async {
    final data = await widget.api.listDatasets();
    if (!mounted) return;
    setState(() => datasets = data);
  }

  Future<void> _upload() async {
    final res = await FilePicker.platform.pickFiles(
      type: FileType.custom,
      allowedExtensions: ['csv'],
    );
    if (res == null || res.files.single.path == null) return;

    setState(() => loading = true);
    try {
      await widget.api.uploadDatasetFile(filePath: res.files.single.path!);
      await _refresh();
      if (!mounted) return;
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(const SnackBar(content: Text('Dataset uploaded')));
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text('Upload error: $e')));
    } finally {
      if (mounted) setState(() => loading = false);
    }
  }

  Future<void> _analyze(String datasetId) async {
    setState(() => loading = true);
    try {
      final r = await widget.api.analyzeDataset(
        datasetId: datasetId,
        limit: 50,
      );
      if (!mounted) return;
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text('Processed: ${r['processed']}')));
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text('Analyze error: $e')));
    } finally {
      if (mounted) setState(() => loading = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Datasets'),
        actions: [
          IconButton(
            onPressed: loading ? null : _refresh,
            icon: const Icon(Icons.refresh),
          ),
        ],
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: loading ? null : _upload,
        child: loading
            ? const CircularProgressIndicator()
            : const Icon(Icons.upload_file),
      ),
      body: ListView.separated(
        itemCount: datasets.length,
        separatorBuilder: (_, __) => const Divider(height: 1),
        itemBuilder: (_, i) {
          final d = datasets[i];
          final id = (d['dataset_id'] ?? '').toString();
          return ListTile(
            title: Text((d['filename'] ?? 'unknown').toString()),
            subtitle: Text('id: $id'),
            trailing: ElevatedButton(
              onPressed: (loading || id.isEmpty) ? null : () => _analyze(id),
              child: const Text('Analyze'),
            ),
          );
        },
      ),
    );
  }
}
