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
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.packet.InboundPacket;
import java.util.Dictionary;
import java.util.Properties;
import static org.onlab.util.Tools.get;
import com.google.common.collect.Maps;
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
    private ApplicationId appId;
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private FlowObjectiveService flowObjectiveService;
    private Map<DeviceId, Map<MacAddress, PortNumber>> macTables = Maps.newConcurrentMap();
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;
    private  PacketProcessor processor ;
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;
    @Activate
    protected void activate() {
        cfgService.registerProperties(getClass());
        appId = coreService.registerApplication("nctu.winlab.bridge");
        processor = new ReactivePacketProcessor();
        packetService.addProcessor(processor, PacketProcessor.director(2));
        requestIntercepts();
    }
    @Deactivate
    protected void deactivate() {
        cfgService.unregisterProperties(getClass(), false);
        packetService.removeProcessor(processor);
        processor=null;
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
            ConnectPoint cp =context.inPacket().receivedFrom();
            MacAddress srcMac = ethPkt.getSourceMAC();
            MacAddress dstMac = ethPkt.getDestinationMAC();
            macTables.putIfAbsent(cp.deviceId(), Maps.newConcurrentMap());
            Map<MacAddress, PortNumber> macTable = macTables.get(cp.deviceId()); 
            if(macTable.get(srcMac)==null){
                macTable.put(srcMac,cp.port());
            }
            PortNumber outPort = macTable.get(dstMac);
            if(outPort==null){
                packetOut(context, PortNumber.FLOOD);
                return;
            }
            else{
                installRule(context, srcMac, dstMac,outPort);
            }  
        }
    }
    private void packetOut(PacketContext context, PortNumber portNumber) {
        context.treatmentBuilder().setOutput(portNumber);
        context.send();
    }
    private void installRule(PacketContext context, MacAddress srcMac,MacAddress dstMac,PortNumber outport){
        Ethernet inPkt = context.inPacket().parsed();
        TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder();
        selectorBuilder.matchEthDst(dstMac);
        TrafficTreatment treatment = DefaultTrafficTreatment.builder().setOutput(outport).build();
        ForwardingObjective forwardingObjective = DefaultForwardingObjective.builder()
                    .withSelector(selectorBuilder.build())
                    .withTreatment(treatment)
                    .withPriority(20)
                    .withFlag(ForwardingObjective.Flag.VERSATILE)
                    .fromApp(appId)
                    .makeTemporary(20) 
                    .add();
            flowObjectiveService.forward(context.inPacket().receivedFrom().deviceId(), forwardingObjective);
          
    }
    private void requestIntercepts() {
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_ARP);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);

        selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);

    }
}