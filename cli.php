<?php

use GeoIp2\Database\Reader;
use Symfony\Component\Console\Helper\ProgressBar;
use Symfony\Component\Console\Output\ConsoleOutput;

require_once "vendor/autoload.php";

$exportedDir = getcwd() . DIRECTORY_SEPARATOR . 'exported';
$sourceDir = getcwd() . DIRECTORY_SEPARATOR . 'logs';

if(!is_dir($sourceDir)) mkdir($sourceDir, 0777, true);
if(!is_dir($exportedDir)) mkdir($exportedDir, 0777, true);

$list = glob("{$sourceDir}/*.{*}", GLOB_BRACE);

foreach($list as $file) {
    $type = mime_content_type($file);

    if($type == 'text/plain' || $type == 'application/csv') {
        parseLog($file, $exportedDir);
    } else if($type == 'application/gzip') {
        extractGz($file);
        parseLog($file, $exportedDir);
    } else {
        throw new Exception("Formato não reconhecido: {$type}, Arquivo: {$file}");
    }

    compactGz($file);
}

/**
 * Função para extrair o gzip
 */
function extractGz(string &$filePath): void
{
    $bufferSize = 4096; // 4k

    $stream = gzopen(
        filename: $filePath,
        mode: 'rb'
    );

    $newName = str_replace('.gz', '.log', $filePath);

    $newFile = fopen($newName, 'wb');

    while(!gzeof($stream)) {
        fwrite(
            $newFile,
            gzread($stream, $bufferSize)
        );
    }

    fclose($newFile);
    fclose($stream);

    unlink($filePath);

    $filePath = $newName;
}

/**
 * Testa e retorna o regex correspondente
 */
function getFromRegex(string $entrada, string $filePath): array
{
    $out = [];

    # IP_Client Client_Identity REMOTE_USER_ID Date(01/Jan/2022) Time(00:00:00) UTC(-0300) URI HTTP_CODE SIZE_BYTES Referer User_Agent
    $regexAccess[] = '/^(\S+) (\S+) (\S+) \[([^:]+):(\d+:\d+:\d+) ([^\]]+)\] \"(.*?)\" (\d+) (\d+) "([^"]*)" "([^"]*)"/';

    # Host Port IP_Client Client_Identity REMOTE_USER_ID Date(01/Jan/2022) Time(00:00:00) UTC(-0300) Verb URI Protocol HTTP_CODE SIZE_BYTES Referer User_Agent
    $regexAccess[] = '/^(\S+):(\d+) (\S+) (\S+) (\S+) \[([^:]+):(\d+:\d+:\d+) ([^\]]+)\] \"(\S+) (.*?) (\S+)\" (\d+) (\d+) "([^"]*)" "([^"]*)"/';

    # IP_Client Client_Identity REMOTE_USER_ID Date(01/Jan/2022) Time(00:00:00) UTC(-0300) Verb URI Protocol HTTP_CODE SIZE_BYTES Referer User_Agent
    $regexAccess[] = '/^(\S+) (\S+) (\S+) \[([^:]+):(\d+:\d+:\d+) ([^\]]+)\] \"(\S+) (.*?) (\S+)\" (\d+) (\d+) "([^"]*)" "([^"]*)"/';

    # IP_Client Client_Identity REMOTE_USER_ID Date(01/Jan/2022) Time(00:00:00) UTC(-0300) URI HTTP_CODE SIZE_BYTES Command User_Agent
    $regexCommand[] = '/^(\S+) (\S+) (\S+) \[([^:]+):(\d+:\d+:\d+) ([^\]]+)\] \"(.*?)\" (\d+) (\d+) (.*?) "([^"]*)"/';

    # Day_Week(Mon) Month(Mar) Day(14) Time(00:00:00) Microtime Year(2022) Core_Type(error) PID TID IP_Client Port_Client Apache_Code Apache_Message
    $regexError[] = '/^\[(\S+) (\S+) (\d+) (\d+:\d+:\d+).(\d+) (\d+)\] \[(\S+)\] \[pid (\d+):tid (\d+)\] \[client (\S+):(\d+)\] (\S+): (.*)/';

    # Day_Week(Mon) Month(Mar) Day(14) Time(00:00:00) Microtime Year(2022) Core_Type(error) PID TID Core_Exception IP_Client Port_Client Apache_Code Apache_Message
    $regexError[] = '/^\[(\S+) (\S+) (\d+) (\d+:\d+:\d+).(\d+) (\d+)\] \[(\S+)\] \[pid (\d+):tid (\d+)\] (.*?) \[client (\S+):(\d+)\] (\S+): (.*)/';

    # Day_Week(Mon) Month(Mar) Day(14) Time(00:00:00) Microtime Year(2022) Core_Type(error) PID TID Core_Exception Apache_Code Apache_Message
    $regexError[] = '/^\[(\S+) (\S+) (\d+) (\d+:\d+:\d+).(\d+) (\d+)\] \[(\S+)\] \[pid (\d+):tid (\d+)\] (.*?): (\S+): (.*)/';

    # Day_Week(Mon) Month(Mar) Day(14) Time(00:00:00) Microtime Year(2022) Core_Type(error) PID TID Apache_Code Apache_Message
    $regexError[] = '/^\[(\S+) (\S+) (\d+) (\d+:\d+:\d+).(\d+) (\d+)\] \[(\S+)\] \[pid (\d+):tid (\d+)\] (\S+): (.*)/';

    # Apache_Code Apache_Message
    $regexError[] = '/^(\S+): (.*)/';

    foreach($regexAccess as $re)
    {
        preg_match($re, $entrada, $test);

        if(sizeof($test) == 12) {
            $location = getClientLocation($test[1]);

            $out = [
                'Type' => 'Access',
                'Host' => '-',
                'Host_Port' => '-',
                'IP_Client' => $test[1],
                'Client_City' => $location->city,
                'Client_State' => $location->state,
                'Client_Country' => $location->country,
                'Client_Country_Code' => $location->country_code,
                'Client_Identity' => $test[2],
                'Remote_User_ID' => $test[3],
                'Date' => $test[4],
                'Time' => $test[5],
                'UTC' => $test[6],
                'Verb' => '-',
                'URI' => $test[7],
                'Protocol' => '-',
                'Http_Code' => $test[8],
                'Size_Bytes' => $test[9],
                'Referer' => $test[10],
                'User_Agent' => $test[11],
            ];

            break;
        } else if(sizeof($test) == 14) {
            $location = getClientLocation($test[1]);

            $out = [
                'Type' => 'Access',
                'Host' => '-',
                'Host_Port' => '-',
                'IP_Client' => $test[1],
                'Client_City' => $location->city,
                'Client_State' => $location->state,
                'Client_Country' => $location->country,
                'Client_Country_Code' => $location->country_code,
                'Client_Identity' => $test[2],
                'Remote_User_ID' => $test[3],
                'Date' => $test[4],
                'Time' => $test[5],
                'UTC' => $test[6],
                'Verb' => $test[7],
                'URI' => $test[8],
                'Protocol' => $test[9],
                'Http_Code' => $test[10],
                'Size_Bytes' => $test[11],
                'Referer' => $test[12],
                'User_Agent' => $test[13],
            ];

            break;
        } else if(sizeof($test) == 16) {
            $location = getClientLocation($test[3]);

            $out = [
                'Type' => 'Access',
                'Host' => $test[1],
                'Host_Port' => $test[2],
                'IP_Client' => $test[3],
                'Client_City' => $location->city,
                'Client_State' => $location->state,
                'Client_Country' => $location->country,
                'Client_Country_Code' => $location->country_code,
                'Client_Identity' => $test[4],
                'Remote_User_ID' => $test[5],
                'Date' => $test[6],
                'Time' => $test[7],
                'UTC' => $test[8],
                'Verb' => $test[9],
                'URI' => $test[10],
                'Protocol' => $test[11],
                'Http_Code' => $test[12],
                'Size_Bytes' => $test[13],
                'Referer' => $test[14],
                'User_Agent' => $test[15],
            ];

            break;
        }
    }

    if(sizeof($out) < 1) {
        foreach($regexError as $re)
        {
            preg_match($re, $entrada, $test);

            if(sizeof($test) == 3) {
                $out = [
                    'Type' => 'Error',
                    'IP_Client' => '-',
                    'Client_City' => "-",
                    'Client_State' => "-",
                    'Client_Country' => "-",
                    'Client_Country_Code' => "-",
                    'Port_Client' => '-',
                    'Date' => "-",
                    'Time' => "-",
                    'Core' => "-",
                    'Core_Exception' => '',
                    'PID' => "-",
                    'TID' => "-",
                    'Apache_Code' => $test[1],
                    'Apache_Message' => $test[2],
                ];
    
                break;
            } else if(sizeof($test) == 12) {
                $out = [
                    'Type' => 'Error',
                    'IP_Client' => '-',
                    'Client_City' => "-",
                    'Client_State' => "-",
                    'Client_Country' => "-",
                    'Client_Country_Code' => "-",
                    'Port_Client' => '-',
                    'Date' => "{$test[3]}/{$test[2]}/{$test[6]}",
                    'Time' => $test[4],
                    'Core' => $test[7],
                    'Core_Exception' => '',
                    'PID' => $test[8],
                    'TID' => $test[9],
                    'Apache_Code' => $test[10],
                    'Apache_Message' => $test[11],
                ];
    
                break;
            } else if(sizeof($test) == 13) {
                $out = [
                    'Type' => 'Error',
                    'IP_Client' => "-",
                    'Client_City' => "-",
                    'Client_State' => "-",
                    'Client_Country' => "-",
                    'Client_Country_Code' => "-",
                    'Port_Client' => "-",
                    'Date' => "{$test[3]}/{$test[2]}/{$test[6]}",
                    'Time' => $test[4],
                    'Core' => $test[7],
                    'Core_Exception' => $test[10],
                    'PID' => $test[8],
                    'TID' => $test[9],
                    'Apache_Code' => $test[11],
                    'Apache_Message' => $test[12],
                ];
    
                break;
            } else if(sizeof($test) == 14) {
                $location = getClientLocation($test[10]);

                $out = [
                    'Type' => 'Error',
                    'IP_Client' => $test[10],
                    'Client_City' => $location->city,
                    'Client_State' => $location->state,
                    'Client_Country' => $location->country,
                    'Client_Country_Code' => $location->country_code,
                    'Port_Client' => $test[11],
                    'Date' => "{$test[3]}/{$test[2]}/{$test[6]}",
                    'Time' => $test[4],
                    'Core' => $test[7],
                    'Core_Exception' => '',
                    'PID' => $test[8],
                    'TID' => $test[9],
                    'Apache_Code' => $test[12],
                    'Apache_Message' => $test[13],
                ];
    
                break;
            } else if(sizeof($test) == 15) {
                $location = getClientLocation($test[11]);

                $out = [
                    'Type' => 'Error',
                    'IP_Client' => $test[11],
                    'Client_City' => $location->city,
                    'Client_State' => $location->state,
                    'Client_Country' => $location->country,
                    'Client_Country_Code' => $location->country_code,
                    'Port_Client' => $test[12],
                    'Date' => "{$test[3]}/{$test[2]}/{$test[6]}",
                    'Time' => $test[4],
                    'Core' => $test[7],
                    'Core_Exception' => $test[10],
                    'PID' => $test[8],
                    'TID' => $test[9],
                    'Apache_Code' => $test[13],
                    'Apache_Message' => $test[14],
                ];
    
                break;
            }
        }
    }

    if(sizeof($out) < 1) {
        foreach($regexCommand as $re)
        {
            preg_match($re, $entrada, $test);

            if(sizeof($test) == 12) {
                $location = getClientLocation($test[1]);

                $out = [
                    'Type' => 'Command',
                    'IP_Client' => $test[1],
                    'Client_City' => $location->city,
                    'Client_State' => $location->state,
                    'Client_Country' => $location->country,
                    'Client_Country_Code' => $location->country_code,
                    'Client_Identity' => $test[2],
                    'Remote_User_ID' => $test[3],
                    'Date' => $test[4],
                    'Time' => $test[5],
                    'UTC' => $test[6],
                    'URI' => $test[7],
                    'Http_Code' => $test[8],
                    'Size_Bytes' => $test[9],
                    'Command' => $test[10],
                    'User_Agent' => $test[11],
                ];
    
                break;
            }
        }
    }

    if(sizeof($out) < 1) {
        throw new Exception("Regex não coincide com entrada. Entrada: {$entrada}, Arquivo: {$filePath}");
    }

    return $out;
}

/**
 * Função para processar o log
 */
function parseLog(string $filePath, string $exportedDir): void
{
    ProgressBar::setFormatDefinition('custom', ' %current%/%max% (%percent:3s%%) -- %message%');

    $outCli = new ConsoleOutput;
    $progressBar = new ProgressBar($outCli);
    $progressBar->setFormat('custom');
    $progressBar->setMaxSteps(count(file($filePath)));

    $progressBar->setMessage(basename($filePath));

    $newName = explode('.', basename($filePath));
    $newName = array_reverse($newName);
    $newName[0] = 'csv';
    $newName = array_reverse($newName);
    $newName = implode('.', $newName);

    $out = $exportedDir . DIRECTORY_SEPARATOR . $newName;

    // pular se já existir esse arquivo
    if(file_exists($out)) {
        $progressBar->start();
        $progressBar->finish();
        echo "\n";

        return ;
    }

    $out = fopen($out, 'w+');

    $stream = fopen($filePath, 'rb');

    $count = 0;

    $progressBar->start();

    while(!feof($stream)) {
        $entrada = trim(fgets($stream));

        if(strlen($entrada) > 0) {
            $line = getFromRegex(
                entrada: $entrada,
                filePath: $filePath
            );

            if($count == 0) {
                $count++;

                fputcsv(
                    $out,
                    array_keys($line),
                    ','
                );
            }

            fputcsv(
                $out,
                array_values($line),
                ','
            );
        }

        $progressBar->advance();
    }

    $progressBar->finish();
    echo "\n";
}

/**
 * Função para compactar em gzip e remover o original
 */
function compactGz(string $filePath): void
{
    $newName = str_replace('.log', '.gz', $filePath);

    $file = gzopen(
        $newName,
        'w9'
    );

    gzwrite($file, file_get_contents($filePath));

    gzclose($file);

    unlink($filePath);
}

/**
 * Retorna cidade do cliente, com base no IP
 */
function getClientLocation(string $ip): ClientLocation
{
    $location = new ClientLocation;

    if(filter_var($ip, FILTER_VALIDATE_IP))
    {
        $reader = new Reader("GeoLite2-City.mmdb");

        try{
            $re = $reader->city($ip);

            $location->city = $re->city->name;
            $location->state = $re->mostSpecificSubdivision->name;
            $location->country = $re->country->name;
            $location->country_code = $re->country->isoCode;
        } catch(\Exception $e){}
    }

    return $location;
}

final class ClientLocation
{
    protected $city = "-";
    protected $state = "-";
    protected $country = "-";
    protected $country_code = "-";

    public function __set(string $prop, mixed $value)
    {
        if (is_string($value) && strlen($value) > 0) $this->$prop = trim($value);
    }

    public function __get(string $prop): string
    {
        return trim($this->$prop);
    }
}