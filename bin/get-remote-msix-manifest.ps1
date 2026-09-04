[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^https://')]
    [string] $Uri
)

$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.Net.Http

$handler = New-Object System.Net.Http.HttpClientHandler
$handler.AllowAutoRedirect = $true
$client = New-Object System.Net.Http.HttpClient($handler)
$client.DefaultRequestHeaders.UserAgent.ParseAdd('Scoop-MSIX-Checkver/1.0')

function Get-RemoteBytes {
    param(
        [Parameter(Mandatory = $true)]
        [long] $Start,
        [Parameter(Mandatory = $true)]
        [long] $End
    )

    $request = New-Object System.Net.Http.HttpRequestMessage(
        [System.Net.Http.HttpMethod]::Get,
        $Uri
    )
    $request.Headers.Range = New-Object System.Net.Http.Headers.RangeHeaderValue($Start, $End)

    try {
        Write-Verbose "Downloading byte range $Start-$End from $Uri"
        $response = $client.SendAsync($request).GetAwaiter().GetResult()
        try {
            if ($response.StatusCode -ne [System.Net.HttpStatusCode]::PartialContent) {
                throw "Server did not honour the HTTP range request for $Uri."
            }
            $bytes = $response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult()
            Write-Verbose "Received $($bytes.Length) bytes."
            return , $bytes
        } finally {
            $response.Dispose()
        }
    } finally {
        $request.Dispose()
    }
}

function Find-SignatureFromEnd {
    param(
        [Parameter(Mandatory = $true)]
        [byte[]] $Bytes,
        [Parameter(Mandatory = $true)]
        [uint32] $Signature
    )

    for ($offset = $Bytes.Length - 4; $offset -ge 0; $offset--) {
        if ([BitConverter]::ToUInt32($Bytes, $offset) -eq $Signature) {
            return $offset
        }
    }
    return -1
}

try {
    $headRequest = New-Object System.Net.Http.HttpRequestMessage(
        [System.Net.Http.HttpMethod]::Head,
        $Uri
    )
    try {
        $headResponse = $client.SendAsync($headRequest).GetAwaiter().GetResult()
        try {
            $headResponse.EnsureSuccessStatusCode() | Out-Null
            $contentLength = [long] $headResponse.Content.Headers.ContentLength
            Write-Verbose "Remote content length is $contentLength bytes."
        } finally {
            $headResponse.Dispose()
        }
    } finally {
        $headRequest.Dispose()
    }

    if ($contentLength -lt 22) {
        throw "Remote file is too small to be an MSIX archive: $Uri"
    }

    $tailLength = [Math]::Min([long] 65557, $contentLength)
    $tailStart = $contentLength - $tailLength
    $tail = Get-RemoteBytes -Start $tailStart -End ($contentLength - 1)
    $eocdOffset = Find-SignatureFromEnd -Bytes $tail -Signature 0x06054b50
    if ($eocdOffset -lt 0) {
        throw "Could not find the ZIP end-of-central-directory record in $Uri."
    }

    $entryCount = [BitConverter]::ToUInt16($tail, $eocdOffset + 10)
    $centralSize = [long] [BitConverter]::ToUInt32($tail, $eocdOffset + 12)
    $centralOffset = [long] [BitConverter]::ToUInt32($tail, $eocdOffset + 16)
    if ($entryCount -eq [uint16]::MaxValue -or
        $centralSize -eq [uint32]::MaxValue -or
        $centralOffset -eq [uint32]::MaxValue) {
        $locatorOffset = $eocdOffset - 20
        if ($locatorOffset -lt 0 -or
            [BitConverter]::ToUInt32($tail, $locatorOffset) -ne 0x07064b50) {
            throw "Could not find the ZIP64 end-of-central-directory locator in $Uri."
        }

        $zip64Offset = [long] [BitConverter]::ToUInt64($tail, $locatorOffset + 8)
        $zip64 = Get-RemoteBytes -Start $zip64Offset -End ($zip64Offset + 55)
        if ([BitConverter]::ToUInt32($zip64, 0) -ne 0x06064b50) {
            throw "Invalid ZIP64 end-of-central-directory record in $Uri."
        }
        $entryCount = [long] [BitConverter]::ToUInt64($zip64, 32)
        $centralSize = [long] [BitConverter]::ToUInt64($zip64, 40)
        $centralOffset = [long] [BitConverter]::ToUInt64($zip64, 48)
    }

    $central = Get-RemoteBytes -Start $centralOffset -End ($centralOffset + $centralSize - 1)
    $entry = $null
    $offset = 0
    while ($offset -lt $central.Length) {
        if ($offset + 46 -gt $central.Length -or
            [BitConverter]::ToUInt32($central, $offset) -ne 0x02014b50) {
            throw "Invalid ZIP central directory in $Uri."
        }

        $flags = [BitConverter]::ToUInt16($central, $offset + 8)
        $method = [BitConverter]::ToUInt16($central, $offset + 10)
        $compressedSize = [BitConverter]::ToUInt32($central, $offset + 20)
        $fileNameLength = [BitConverter]::ToUInt16($central, $offset + 28)
        $extraLength = [BitConverter]::ToUInt16($central, $offset + 30)
        $commentLength = [BitConverter]::ToUInt16($central, $offset + 32)
        $localHeaderOffset = [BitConverter]::ToUInt32($central, $offset + 42)
        $encoding = if (($flags -band 0x0800) -ne 0) {
            [Text.Encoding]::UTF8
        } else {
            [Text.Encoding]::ASCII
        }
        $fileName = $encoding.GetString($central, $offset + 46, $fileNameLength)

        if ($fileName -ceq 'AppxManifest.xml') {
            $entry = @{
                Method            = $method
                CompressedSize    = [long] $compressedSize
                LocalHeaderOffset = [long] $localHeaderOffset
            }
            break
        }

        $offset += 46 + $fileNameLength + $extraLength + $commentLength
    }

    if ($null -eq $entry) {
        throw "AppxManifest.xml was not found in $Uri."
    }

    $localHeader = Get-RemoteBytes -Start $entry.LocalHeaderOffset -End ($entry.LocalHeaderOffset + 29)
    if ([BitConverter]::ToUInt32($localHeader, 0) -ne 0x04034b50) {
        throw "Invalid ZIP local header for AppxManifest.xml in $Uri."
    }
    $localNameLength = [BitConverter]::ToUInt16($localHeader, 26)
    $localExtraLength = [BitConverter]::ToUInt16($localHeader, 28)
    $dataOffset = $entry.LocalHeaderOffset + 30 + $localNameLength + $localExtraLength
    $compressed = Get-RemoteBytes -Start $dataOffset -End ($dataOffset + $entry.CompressedSize - 1)

    if ($entry.Method -eq 0) {
        $manifestBytes = $compressed
    } elseif ($entry.Method -eq 8) {
        $compressedStream = New-Object System.IO.MemoryStream(, $compressed)
        try {
            $deflate = New-Object System.IO.Compression.DeflateStream(
                $compressedStream,
                [System.IO.Compression.CompressionMode]::Decompress
            )
            try {
                $output = New-Object System.IO.MemoryStream
                try {
                    $deflate.CopyTo($output)
                    $manifestBytes = $output.ToArray()
                } finally {
                    $output.Dispose()
                }
            } finally {
                $deflate.Dispose()
            }
        } finally {
            $compressedStream.Dispose()
        }
    } else {
        throw "Unsupported compression method $($entry.Method) for AppxManifest.xml."
    }

    $manifestText = [Text.Encoding]::UTF8.GetString($manifestBytes).TrimStart([char] 0xFEFF)
    [xml] $manifest = $manifestText
    $application = $manifest.Package.Applications.Application | Select-Object -First 1
    [pscustomobject] @{
        Identity     = [string] $manifest.Package.Identity.Name
        Version      = [string] $manifest.Package.Identity.Version
        Architecture = [string] $manifest.Package.Identity.ProcessorArchitecture
        Executable   = [string] $application.Executable
    }
} finally {
    $client.Dispose()
    $handler.Dispose()
}
