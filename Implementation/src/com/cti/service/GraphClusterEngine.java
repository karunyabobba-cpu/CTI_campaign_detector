package com.cti.service;

import com.cti.model.CampaignCluster;
import com.cti.model.Indicator;
import java.util.*;
import java.util.stream.Collectors;

public class GraphClusterEngine {

    public List<CampaignCluster> detectCampaignClusters(List<Indicator> indicators, List<Set<String>> edges) {
        Map<String, Indicator> nodeMap = indicators.stream()
                .collect(Collectors.toMap(i -> i.getValue().toLowerCase(), i -> i, (a, b) -> a));

        Map<String, Set<String>> adjacencyList = new HashMap<>();
        for (String key : nodeMap.keySet()) {
            adjacencyList.put(key, new HashSet<>());
        }

        for (Set<String> edgeGroup : edges) {
            for (String u : edgeGroup) {
                for (String v : edgeGroup) {
                    if (!u.equals(v) && adjacencyList.containsKey(u) && adjacencyList.containsKey(v)) {
                        adjacencyList.get(u).add(v);
                        adjacencyList.get(v).add(u);
                    }
                }
            }
        }

        for (String nodeA : nodeMap.keySet()) {
            if (nodeA.contains("@")) {
                String domainPart = nodeA.substring(nodeA.indexOf("@") + 1);
                if (adjacencyList.containsKey(domainPart)) {
                    adjacencyList.get(nodeA).add(domainPart);
                    adjacencyList.get(domainPart).add(nodeA);
                }
            }
        }

        Set<String> visited = new HashSet<>();
        List<CampaignCluster> clusters = new ArrayList<>();
        int campaignIndex = 1;

        for (String startNode : adjacencyList.keySet()) {
            if (!visited.contains(startNode)) {
                String cid = String.format("CAMP-%03d", campaignIndex++);
                CampaignCluster cluster = new CampaignCluster(cid, "Coordinated Campaign #" + (campaignIndex - 1));

                Queue<String> queue = new LinkedList<>();
                queue.add(startNode);
                visited.add(startNode);

                while (!queue.isEmpty()) {
                    String curr = queue.poll();
                    cluster.addIndicator(nodeMap.get(curr));

                    for (String neighbor : adjacencyList.get(curr)) {
                        if (!visited.contains(neighbor)) {
                            visited.add(neighbor);
                            queue.add(neighbor);
                        }
                    }
                }
                clusters.add(cluster);
            }
        }
        return clusters;
    }
}