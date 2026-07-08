package com.rasp.server.repository;

import com.rasp.server.model.AgentInfo;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * Agent 信息数据仓库
 */
@Repository
public interface AgentInfoRepository extends JpaRepository<AgentInfo, Long> {

    /** 根据 agentId 查找 */
    Optional<AgentInfo> findByAgentId(String agentId);

    /** 根据状态查找 */
    java.util.List<AgentInfo> findByStatus(String status);

    /** 统计在线 Agent 数量 */
    long countByStatus(String status);
}
