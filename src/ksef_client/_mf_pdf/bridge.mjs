import { stdin, stdout } from 'node:process';
// The upstream browser parser only needs FileReader.readAsText under Node.
globalThis.FileReader = class {
  readAsText(blob, encoding = 'utf-8') {
    blob.arrayBuffer().then(bytes => {
      this.result = new TextDecoder(encoding).decode(bytes);
      this.onload?.({ target: this });
    }).catch(error => this.onerror?.(error));
  }
};
try {
  const chunks = [];
  for await (const chunk of stdin) chunks.push(chunk);
  const input = Buffer.concat(chunks);
  const separator = input.indexOf(10);
  const { kind, additionalData } = JSON.parse(input.subarray(0, separator).toString('utf8'));
  const file = new File([input.subarray(separator + 1)], 'document.xml', { type: 'application/xml' });
  const { generateInvoice, generatePDFUPO } = await import('./generator.mjs');
  const pdf = kind === 'invoice'
    ? await generateInvoice(file, additionalData, 'blob')
    : await generatePDFUPO(file);
  stdout.write(Buffer.from(await pdf.arrayBuffer()));
} catch {
  // XML and verification URLs must not appear in process diagnostics.
  process.stderr.write('MF PDF generation failed.');
  process.exitCode = 1;
}
