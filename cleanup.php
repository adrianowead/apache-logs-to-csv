<?php

use Symfony\Component\Console\Helper\ProgressBar;
use Symfony\Component\Console\Output\ConsoleOutput;

require_once "vendor/autoload.php";

$exportedDir = getcwd() . DIRECTORY_SEPARATOR . 'exported';
$mergedDir = getcwd() . DIRECTORY_SEPARATOR . 'merged';

if(!is_dir($exportedDir)) mkdir($exportedDir, 0777, true);
if(!is_dir($mergedDir)) mkdir($mergedDir, 0777, true);

$files = array_values( preg_grep('/^((?!-merged.csv).)*$/', glob("{$exportedDir}/*[-access.|-error.]*.csv")) );

/**
 * Agrupar similares
 */
foreach($files as $k => $file) {
    $base = basename($file);

    $meta = metaphone($base, 10);

    if(substr_count($base, '-access') > 0) {
        $meta .= '-access';
    } else if(substr_count($base, '-error') > 0) {
        $meta .= '-error';
    }

    $files[$meta][] = $file;
    unset($files[$k]);
}

$files = array_values($files);

/**
 * Mesclar arquivos similares
 */
foreach($files as $group) {
    if(substr_count(basename($group[0]), '-access') > 0) {
        $newFileName = preg_split('/(-access)/', basename($group[0]))[0];
        $newFileNameCsv = "{$newFileName}-access-merged.csv";
    } else if(substr_count(basename($group[0]), '-error') > 0) {
        $newFileName = preg_split('/(-error)/', basename($group[0]))[0];
        $newFileNameCsv = "{$newFileName}-error-merged.csv";
    }

    $fileOutPath = $mergedDir . DIRECTORY_SEPARATOR . $newFileNameCsv;

    $fileOut = fopen($fileOutPath, 'w+');

    ProgressBar::setFormatDefinition('custom', ' %current%/%max% (%percent:3s%%) -- %message%');

    $outCli = new ConsoleOutput;
    $progressBar = new ProgressBar($outCli);
    $progressBar->setFormat('custom');

    $maxSteps = 0;

    foreach($group as $fileName) {
        $maxSteps += count(file($fileName));
    }

    $progressBar->setMaxSteps($maxSteps);
    $progressBar->setMessage($newFileNameCsv);

    $header = [];

    foreach($group as $fileName) {
        $file = fopen($fileName, 'rb');
        $delimiter = detectDelimiter($fileName);

        while(!feof($file)) {
            $line = fgetcsv($file, 1000000, $delimiter);

            if(is_array($line) && $line != $header) {
                fputcsv(
                    $fileOut,
                    $line,
                    ","
                );
            }

            if(sizeof($header) == 0 && is_array($line)) {
                $header = $line;
            }

            $progressBar->advance();
        }
    }

    compactGz($fileOutPath);

    $progressBar->finish();
    echo "\n";
}

/**
* @param string $csvFile Path to the CSV file
* @return string Delimiter
*/
function detectDelimiter($csvFile)
{
    $delimiters = [";" => 0, "," => 0, "\t" => 0, "|" => 0];

    $handle = fopen($csvFile, "r");
    $firstLine = fgets($handle);
    fclose($handle); 
    foreach ($delimiters as $delimiter => &$count) {
        $count = count(str_getcsv($firstLine, $delimiter));
    }

    return array_search(max($delimiters), $delimiters);
}

/**
 * Função para compactar em gzip e remover o original
 */
function compactGz(string $filePath): void
{
    $newName = str_replace('.csv', '.csv.gz', $filePath);

    $file = gzopen(
        $newName,
        'w9'
    );

    gzwrite($file, file_get_contents($filePath));

    gzclose($file);

    unlink($filePath);
}