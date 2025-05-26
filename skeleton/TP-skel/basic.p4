/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4> // Source: https://github.com/p4lang/p4c/blob/main/p4include/v1model.p4

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_TELEMETRY = 0x801;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

const int MAX_HOPS = 255;
const int SIZEOF_TELEMETRY_ITEM = 48 + 9 + 9 + 6; // How come there is no sizeof?
header telemetry_item {
    bit<48> ingress_global_timestamp; // As defined in v1model.p4
    bit<9> ingress_port;              // As defined in v1model.p4
    bit<9> egress_port;               // As defined in v1model.p4
    // TODO: switch_id
    bit<6> padding;
}

header telemetry_header_t {
    bit<8> item_count; // Number of telemetry items in the telemetry list (each one corresponds to a router hop)
}

struct metadata {
    bit<8> parsed_telemetry_item_count;
}

struct headers {
    ethernet_t   ethernet;
    telemetry_header_t telemetry_header;
    telemetry_item[MAX_HOPS] telemetry_items;
    ipv4_t       ipv4;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: mark_no_telemetry;
            TYPE_TELEMETRY: parse_telemetry_header;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }

    state mark_no_telemetry {
        hdr.telemetry_header.setInvalid();
        transition parse_ipv4;
    }

    state parse_telemetry_header {
        packet.extract(hdr.telemetry_header);
        meta.parsed_telemetry_item_count = 0;

        transition select(hdr.telemetry_header.item_count) {
            0: parse_ipv4;
            default: parse_telemetry_item;
        }
    }

    state parse_telemetry_item {
        packet.extract(hdr.telemetry_items.next);
        meta.parsed_telemetry_item_count = meta.parsed_telemetry_item_count + 1;

        transition select(meta.parsed_telemetry_item_count == hdr.telemetry_header.item_count) {
            true: parse_ipv4;
            false: parse_telemetry_item;
        }
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;

        // Telemetry logic
        if (hdr.telemetry_header.isValid() && hdr.telemetry_header.item_count > 0) {
            // TODO: Update metrics
        } else {
            // TODO: Set telemetry headers. Read them from https://github.com/p4lang/behavioral-model/blob/main/docs/simple_switch.md#intrinsic_metadata-header
            hdr.telemetry_header.setValid();
            hdr.telemetry_items[0].setValid();

            hdr.ethernet.etherType = TYPE_TELEMETRY;
            hdr.telemetry_header.item_count = 1;

            hdr.telemetry_items[0] = {
                standard_metadata.ingress_global_timestamp,
                standard_metadata.ingress_port,
                standard_metadata.egress_port,
                0
            };
        }
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.telemetry_header);
        packet.emit(hdr.telemetry_items);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
