# Hubcap

**Packet Capture Hub**: A webpage that can search all downloadable pcaps from
packetlife and Wireshark samples.

Current progress:

```mermaid
graph TD
    %%Elements
    subgraph get_dl_links.go
    PL(Get Packet Life Links)
    WSS(Get WS Sample Links)
    WBD(WS Bug Database files)
    DM(Multiplex Link Data)
    end

    subgraph dl_files.go
    IC{In Cache?}
    DLF(Download Files to TempDir)
    end

    subgraph get_pcap_info.go
    WSINT(capinfos tshark)
    end

    subgraph gen_html.go = Make HTML from parts
    JPI(JSONify Pcap Info)
    SP(Searchable Download Page)
    WJS(JS to dynamically search JSON)
    end

    %% Relationships
    PL -- links + descriptions --> DM
    WSS -- links + descriptions --> DM
    WBD -- links + descriptions --> DM
    DM -- links--> IC
    IC -- Not in Cache --> DLF
    IC -- Use cached --> JPI
    DM --descriptions--> JPI
    DLF -- filepath list --> WSINT
    WSINT --pcap metadata--> JPI
    JPI -- pcap JSON --> SP
    WJS -- JS --> SP

    %%CSS
    linkStyle default interpolate monotoneX
    classDef done fill:#D4EFDF,stroke:#1B4F72;
    classDef doing fill:#FCF3CF,stroke:#1B4F72;
    class PL,WSS,DM done
    class DLF doing
```

<!-- Backup
![](https://mermaidjs.github.io/mermaid-live-editor/#/edit/eyJjb2RlIjoiZ3JhcGggVERcbiUlRWxlbWVudHNcbnN1YmdyYXBoIHBhcnNlX2xpbmtzLmdvID0gR2V0IExpbmtzIGZyb20gSFRNTFxuUEwoR2V0IFBhY2tldCBMaWZlIExpbmtzKVxuV1NTKEdldCBXaXJlc2hhcmsgU2FtcGxlIExpbmtzKVxuRE0oRGF0YSBNdWx0aXBsZXhlcilcbmVuZFxuXG5zdWJncmFwaCBkbF9maWxlcy5nb1xuRExGKERvd25sb2FkIEZpbGVzIHRvIFRlbXBEaXIpXG5lbmRcblxuc3ViZ3JhcGggZ2V0X3BjYXBfaW5mby5nb1xuQ0FQSShjYXBpbmZvcylcblRTSEkodHNoYXJrKVxuZW5kXG5cbnN1YmdyYXBoIGdlbl9odG1sLmdvID0gTWFrZSBIVE1MIGZyb20gcGFydHNcbkpQSShKU09OaWZ5IFBjYXAgSW5mbylcblNQKFNlYXJjaGFibGUgRG93bmxvYWQgUGFnZSlcbldKUyhKUyB0byBkeW5hbWljYWxseSBzZWFyY2ggSlNPTilcbmVuZFxuXG4lJSBSZWxhdGlvbnNoaXBzXG5QTCAtLSBsaW5rcyArIGRlc2NyaXB0aW9ucyAtLT4gRE1cbldTUyAtLSBsaW5rcyArIGRlc2NyaXB0aW9ucyAtLT4gRE1cbkRNIC0tIGxpbmtzLS0-IERMRlxuRE0gLS1kZXNjcmlwdGlvbnMtLT4gSlBJXG5ETEYgLS0gZmlsZXBhdGggbGlzdCAtLT4gQ0FQSVxuRExGIC0tIGZpbGVwYXRoIGxpc3QgLS0-IFRTSElcbkNBUEkgLS1wY2FwIG1ldGFkYXRhLS0-IEpQSVxuVFNISSAtLXBjYXAgc3RhdHMgLS0-IEpQSVxuSlBJIC0tIHBjYXAgSlNPTiAtLT4gU1BcbldKUyAtLSBKUyAtLT4gU1BcblxuJSVDU1NcbmxpbmtTdHlsZSBkZWZhdWx0IGludGVycG9sYXRlIG1vbm90b25lWFxuY2xhc3NEZWYgZG9uZSBmaWxsOiNENEVGREYsc3Ryb2tlOiMxQjRGNzI7XG5jbGFzc0RlZiBkb2luZyBmaWxsOiNGQ0YzQ0Ysc3Ryb2tlOiMxQjRGNzI7XG5jbGFzcyBQTCBkb25lXG5jbGFzcyBXU1MgZG9pbmciLCJtZXJtYWlkIjp7InRoZW1lIjoibmV1dHJhbCJ9fQ)
-->
