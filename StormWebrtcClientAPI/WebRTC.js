
var _webrtc_array = [];

var _webrtc_sdp = `v=0
o=- 0 2 IN IP4 0.0.0.0
s=-
t=0 0
a=group:BUNDLE data
a=msid-semantic: WMS
m=application 9 DTLS/SCTP 5000
c=IN IP4 0.0.0.0
a=ice-ufrag:7GEO
a=ice-pwd:3S0OeHDz16aoWRK4tnALIsebH4nk9olF
a=setup:passive
a=mid:data
a=sctpmap:5000 webrtc-datachannel 1024
`;

function StormWebrtcOpen(index) {
    Module.ccall('HandleStormWebrtcConnect', 'null', ['number'], [index]);
}

function StormWebrtcData(index, stream_index, sender, msg) {
    var l = msg.byteLength;
    var ptr = Module._malloc(l);
    var buffer = new Uint8Array(msg);
    Module.writeArrayToMemory(buffer, ptr);
    Module.ccall('HandleStormWebrtcMessage', 'null', ['number', 'number', 'number', 'number', 'number'], [index, stream_index, sender?1:0, ptr, l]);
}

function StormWebrtcSendBinaryMessage(index, stream, sender, ptr, length) {
    var packet = HEAPU8.slice(ptr, ptr + length);

    if(sender != 0) {
        _webrtc_array[index].inc_channels[stream].send(packet);
    } else {
        _webrtc_array[index].out_channels[stream].send(packet);
    }
}

function StormWebrtcCheckConnected(index) {
    if(_webrtc_array[index].connected) {
        return;
    }

    for(var stream = 0; stream < _webrtc_array[index].inc_created.length; stream++) {
        if(_webrtc_array[index].inc_created[stream] == false) {
            return;
        }
    }

    for(var stream = 0; stream < _webrtc_array[index].out_created.length; stream++) {
        if(_webrtc_array[index].out_created[stream] == false) {
            return;
        }
    } 

    _webrtc_array[index].connected = true;
    
    Module.ccall('HandleStormWebrtcConnect', 'null', ['number'], [index]);
}

function StormWebrtcConnectFailure(index) {
    Module.ccall('HandleStormWebrtcDisconnect', 'null', ['number'], [index]); 
}

function StormWebrtcCheckDisconnect(index) {
    if(_webrtc_array[index].connected && _webrtc_array[index].dead == false) {
        Module.ccall('HandleStormWebrtcDisconnect', 'null', ['number'], [index]);
        _webrtc_array[index].connected = false;
    }    
}

function StormWebrtcCreateConnection(index, ipaddr_ptr, fingerprint_ptr, port, inc_types_ptr, inc_types_len, out_types_ptr, out_types_len) {

    var ipaddr = Module.UTF8ToString(ipaddr_ptr);
    var fingerprint = Module.UTF8ToString(fingerprint_ptr);

    while(_webrtc_array.length <= index) {
        _webrtc_array.push(null);
    }

    let webrtc_index = index;

    _webrtc_array[index] = {};
    _webrtc_array[index].connection = new RTCPeerConnection();
    _webrtc_array[index].connected = false;
    _webrtc_array[index].dead = false;
    _webrtc_array[index].inc_types = HEAPU8.slice(inc_types_ptr, inc_types_ptr + inc_types_len);
    _webrtc_array[index].out_types = HEAPU8.slice(out_types_ptr, out_types_ptr + out_types_len);

    _webrtc_array[index].inc_created = [];
    _webrtc_array[index].inc_channels = [];
    for(var stream = 0; stream < inc_types_len; stream++) {
        _webrtc_array[index].inc_created.push(false);
        _webrtc_array[index].inc_channels.push(null);
    }

    _webrtc_array[index].out_created = [];
    _webrtc_array[index].out_channels = [];
    for(var stream = 0; stream < out_types_len; stream++) {
        _webrtc_array[index].out_created.push(false);

        var channel_options = {};
        channel_options.id = stream * 2;

        if(_webrtc_array[index].out_types[stream] == 0) {
            channel_options.ordered = true;
        } else {
            channel_options.ordered = false;            
        }
        
        let stream_index = index;

        var out_channel = _webrtc_array[index].connection.createDataChannel(stream, channel_options);
        out_channel.onopen = function(event) {
            _webrtc_array[webrtc_index].out_created[stream_index] = true;
            StormWebrtcCheckConnected(webrtc_index);
        }

        _webrtc_array[webrtc_index].inc_channels[stream_index].onmessage = function(event) {
            StormWebrtcData(webrtc_index, stream_index, true, event.data);
        }        

        out_channel.onclose = function(event) {
            StormWebrtcCheckDisconnect(webrtc_index);
        }

        out_channel.onerror = function(event) {
            StormWebrtcCheckDisconnect(webrtc_index);
        }

        _webrtc_array[index].out_channels.push(out_channel);
    }

    _webrtc_array[index].connection.ondatachannel = function(event) {
        var channel = event.channel;
        let stream_index = Math.floor(channel.id / 2);
        _webrtc_array[webrtc_index].inc_channels[stream_index] = channel;
        _webrtc_array[webrtc_index].inc_channels[stream_index].onopen = function() {
            _webrtc_array[webrtc_index].inc_created[stream_index] = true;

            _webrtc_array[webrtc_index].inc_channels[stream_index].onmessage = function(event) {
                StormWebrtcData(webrtc_index, stream_index, false, event.data);
            }

            _webrtc_array[webrtc_index].inc_channels[stream_index].onclose = function(event) {
                StormWebrtcCheckDisconnect(webrtc_index);
            }

            _webrtc_array[webrtc_index].inc_channels[stream_index].onerror = function(event) {
                StormWebrtcCheckDisconnect(webrtc_index);
            }

            StormWebrtcCheckConnected(webrtc_index);
        }
    } 

    _webrtc_array[index].connection.oniceconnectionstatechange = function(event) {
        if(_webrtc_array[webrtc_index].connection.iceConnectionState == "disconnected") {
            if(_webrtc_array[index].dead == false)
            {
                Module.ccall('HandleStormWebrtcDisconnect', 'null', ['number'], [index]);
                _webrtc_array[index].connected = false;
            }
        }
    }

    let sdp = _webrtc_sdp + "a=fingerprint:sha-256 " + fingerprint + "\n";
 
    _webrtc_array[index].connection.createOffer().then(function(offer) { 
        var lines = offer.sdp.split('\n');
        for(var index = 0; index < lines.length; index++) {
            if(lines[index].substr(0, 10) == "a=ice-pwd:") {
                lines[index] = "a=ice-pwd:3S0OeHDz16aoWRK4tnALIsebH4nk9olF";
            }
        }

        offer.sdp = lines.join("\n");

        _webrtc_array[webrtc_index].connection.setLocalDescription(offer).then(function() {
            var desc = {'sdp': sdp, 'type': 'answer'};
            _webrtc_array[webrtc_index].connection.setRemoteDescription(desc).then(function() {
                var ice_candidate = {
                    'candidate': "a=candidate:0 1 UDP 1 "+ipaddr+" "+port+" typ host",
                    'sdpMid': "data",
                    'sdpMLineIndex': 0
                };

                _webrtc_array[webrtc_index].connection.addIceCandidate(new RTCIceCandidate(ice_candidate));
            }, function(exception) { StormWebrtcConnectFailure(webrtc_index); });
        }, function(exception) { StormWebrtcConnectFailure(webrtc_index); }); 
    }, function(exception) { StormWebrtcConnectFailure(webrtc_index); });
}

function StormWebrtcDestroyConnection(index) {
    _webrtc_array[index].dead = true;
    _webrtc_array[index].connection.ondatachannel = null;
    _webrtc_array[index].connection.onconnectionstatechange = null;
    _webrtc_array[index].connection.close();
    _webrtc_array[index] = null;
}
