import fs from 'fs';
import { dnssecLookUp, Question, SecurityStatus } from '@relaycorp/dnssec';
import { DNSoverHTTPS } from 'dohdec';
import { lookupTxt } from 'dns-query';
import CsvReadableStream from 'csv-reader';
import { createArrayCsvWriter } from 'csv-writer';

const doh = new DNSoverHTTPS({ url: 'https://cloudflare-dns.com/dns-query' });
const dnsServers = ['dns.google', 'dns.switch.ch'];

async function getARecord(domain) {
  return await dnssecLookUp(new Question(domain, 'A'), async (question) =>
    doh.lookup(question.name, {
      rrtype: question.getTypeName(),
      json: false, // Request DNS message in wire format
      decode: false, // Don't parse the DNS message
      dnssec: true, // Retrieve RRSIG records
    })
  );
}

function sleep(time) {
  return new Promise((resolve) => setTimeout(resolve, time));
}

async function lookupBatch(domainNames, writer, batchSize, sleepTime) {
  let finalResult = [];
  const batches = Array.from(
    { length: Math.ceil(domainNames.length / batchSize) },
    (_, i) => domainNames.slice(i * batchSize, (i + 1) * batchSize)
  );

  for (const [index, batch] of batches.entries()) {
    console.log('batch no: ', index + 1, '/', batches.length);
    await sleep(sleepTime);
    const promises = batch.map(async (domainName) => {
      let isDNSSEC = false;
      try {
        const result = await getARecord(domainName);
        if (result.status === SecurityStatus.SECURE) {
          console.log(`${domainName}/A =`, result.result);
          isDNSSEC = true;
        } else {
          const reason = result.reasonChain.join(', ');
          console.error(
            `DNSSEC verification for ${domainName}/A failed: ${reason}`
          );
          isDNSSEC = false;
        }
      } catch (error) {
        console.log('error', error.message);
        isDNSSEC = false;
      }
      let TXTSet = [];
      try {
        const { entries } = await lookupTxt(domainName, {
          endpoints: dnsServers,
        });
        TXTSet = entries.filter((entry) => entry.data.startsWith('ENS1'));
      } catch (error) {}
      return [domainName, isDNSSEC, TXTSet[0]?.data];
    });

    let result = await Promise.all(promises);
    let filteredResult = result.filter(Boolean);
    console.log('filteredResult', filteredResult);
    if (filteredResult.length > 0) {
      finalResult = [...finalResult, ...filteredResult];
    }
  }
  await writer.writeRecords(finalResult);
}

const regex = /\[\'(.*)\',\'TXT\'\]/i;

function evaluateCSV({ input, output, batchSize, sleepTime }) {
  const inputStream = fs.createReadStream(input, 'utf8');
  const csvWriter = createArrayCsvWriter({
    path: output,
    header: ['Domain', 'DNSSEC', 'TXTRecord'],
  });

  let domains = [];
  inputStream
    .pipe(
      new CsvReadableStream({
        trim: true,
      })
    )
    .on('data', function (row) {
      const domain = row[17].replace(regex, '$1');
      if (
        domain.includes('.') &&
        !domain.startsWith('.') &&
        !domain.endsWith('.') &&
        !domain.includes('@')
      ) {
        domains.push(domain);
      }
    })
    .on('end', function () {
      domains = [...new Set(domains)];
      console.log('No more rows!');
      lookupBatch(domains, csvWriter, batchSize, sleepTime);
    });
}

evaluateCSV({
  input: 'resolve_events.csv',
  output: 'results.csv',
  batchSize: 200,
  sleepTime: 200,
});
