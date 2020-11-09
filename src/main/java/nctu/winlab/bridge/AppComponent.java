/*
 * Copyright 2020-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nctu.winlab.bridge;
import com.google.common.collect.ImmutableSet;
import org.onosproject.cfg.ComponentConfigService;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.onlab.packet.Ethernet;
import org.onlab.packet.ICMP;
import org.onlab.packet.IPv4;
import org.onlab.packet.MacAddress;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.event.Event;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Host;
import org.onosproject.net.HostId;
import org.onosproject.net.Link;
import org.onosproject.net.Path;
import org.onosproject.net.PortNumber;
import org.onosproject.net.host.HostService;
import org.onosproject.net.topology.TopologyService;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.FlowEntry;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.packet.InboundPacket;
import java.util.Dictionary;
import java.util.Properties;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.edge.EdgePortEvent;
import org.onosproject.net.edge.EdgePortListener;
import org.onosproject.net.edge.EdgePortService;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.IpAddress;
import static org.onlab.util.Tools.get;
import com.google.common.collect.Maps;
import org.onlab.packet.ARP;
import java.nio.ByteBuffer;

import java.util.Map;
import java.util.HashMap;
/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true,
           service = {AppComponent.class},
           property = {
               "someProperty=Some Default String Value",
           })
public class AppComponent {
    private final Logger log = LoggerFactory.getLogger(getClass());
    /** Some configurable property. */
    private String someProperty;
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ComponentConfigService cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private FlowObjectiveService flowObjectiveService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected EdgePortService edgeService;
    private ReactivePacketProcessor processor = new ReactivePacketProcessor();
    private static HashMap<Ip4Address,ConnectPoint	> mc;
    private static HashMap<Ip4Address,MacAddress> mi;
    int i=0;
    private ApplicationId appId;
    @Activate
    protected void activate() {
        cfgService.registerProperties(getClass());
        appId = coreService.registerApplication("nctu.winlab.bridge");
        packetService.addProcessor(processor, PacketProcessor.director(2));
        requestIntercepts();
        mc =new HashMap<Ip4Address, ConnectPoint>();
        mi =new HashMap<Ip4Address,MacAddress>();

    }
    @Deactivate
    protected void deactivate() {
        cfgService.unregisterProperties(getClass(), false);
        packetService.removeProcessor(processor);
        withdrawIntercepts();
        processor=null;
    }
    
    @Modified
    public void modified(ComponentContext context) {
        Dictionary<?, ?> properties = context != null ? context.getProperties() : new Properties();
        if (context != null) {
            someProperty = get(properties, "someProperty");
        }
        log.info("Reconfigured");
    }

    private class ReactivePacketProcessor implements PacketProcessor {
    @Override
        public void process(PacketContext context) {
            if (context.isHandled()) {
                return;
            }   
            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();
            if (ethPkt == null) {
                return;
            }
            Ip4Address srcIP = Ip4Address.valueOf​(((ARP)ethPkt.getPayload()).getSenderProtocolAddress());
            Ip4Address dstIP = Ip4Address.valueOf​(((ARP)ethPkt.getPayload()).getTargetProtocolAddress());
            if(mi.get(srcIP) == null){ //learn MAC mapping
                log.info("put {},{} in table",srcIP.toString(),ethPkt.getSourceMAC().toString());
                mi.put(srcIP,ethPkt.getSourceMAC());
                mc.put(srcIP,context.inPacket().receivedFrom());
            }
            if(mi.get(dstIP)==null){
                log.info("flood packet");
                for(ConnectPoint p : edgeService.getEdgePoints()){
                    if(p == context.inPacket().receivedFrom())
                        continue;
                    send(p,pkt);
                }
            }
            if(mi.get(dstIP)!=null && ((ARP)ethPkt.getPayload()).getOpCode()==(short)1){
                log.info("ARP supression");
                Ethernet reply = (ARP.buildArpReply(dstIP,mi.get(dstIP),ethPkt));
                TrafficTreatment.Builder builder = DefaultTrafficTreatment.builder();
                ConnectPoint sourcePoint = context.inPacket().receivedFrom();
                builder.setOutput(sourcePoint.port());
                context.block();
                packetService.emit(new DefaultOutboundPacket(sourcePoint.deviceId(),
                        builder.build(), ByteBuffer.wrap(reply.serialize())));
            }
            else if(mi.get(dstIP)!=null && ((ARP)ethPkt.getPayload()).getOpCode()==(short)2){
                log.info("unicast");
                TrafficTreatment.Builder builder = DefaultTrafficTreatment.builder();
                builder.setOutput(mc.get(dstIP).port());
                context.block();
                packetService.emit(new DefaultOutboundPacket(mc.get(dstIP).deviceId(),
                        builder.build(), pkt.unparsed()));
            }
        }
    }
    private void packetOut(PacketContext context, PortNumber portNumber) {
        context.treatmentBuilder().setOutput(portNumber);
        context.send();
    }
    private void requestIntercepts() {
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_ARP);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);
    }
    private void send(ConnectPoint p, InboundPacket pkt) {    
        TrafficTreatment.Builder builder = DefaultTrafficTreatment.builder();
        builder.setOutput(p.port());
        packetService.emit(
            new DefaultOutboundPacket(
            p.deviceId(),
            builder.build(),
            pkt.unparsed()
            )
        );
    }
    private void withdrawIntercepts() {
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_ARP);
        packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);
    }
}