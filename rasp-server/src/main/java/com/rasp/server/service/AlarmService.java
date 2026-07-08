package com.rasp.server.service;

import com.rasp.commons.AlarmEvent;
import com.rasp.server.model.AlarmRecord;
import com.rasp.server.repository.AlarmRecordRepository;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

/**
 * 告警管理服务
 */
@Service
public class AlarmService {

    private final AlarmRecordRepository repository;

    public AlarmService(AlarmRecordRepository repository) {
        this.repository = repository;
    }

    /**
     * 从 AlarmEvent 创建告警记录 (Agent 上报时调用)
     */
    @Transactional
    public AlarmRecord createFromEvent(AlarmEvent event) {
        AlarmRecord record = new AlarmRecord();
        record.setAttackType(event.getAttackType() != null ? event.getAttackType().name() : "UNKNOWN");
        record.setSeverity(event.getSeverity() != null ? event.getSeverity().name() : "MEDIUM");
        record.setTitle(event.getTitle());
        record.setDescription(event.getDescription());
        record.setBlocked(event.isBlocked());
        record.setSourceIp(event.getSourceIp());
        record.setAppName(event.getAppName());
        record.setHttpMethod(event.getHttpMethod());
        record.setHttpPath(event.getHttpPath());
        record.setPayload(event.getPayload());
        record.setStackTrace(event.getStackTrace());
        record.setTimestamp(event.getTimestamp() != null ? event.getTimestamp() : LocalDateTime.now());
        return repository.save(record);
    }

    /**
     * 分页查询告警列表
     */
    public List<AlarmRecord> listAlarms(int page, int pageSize) {
        return repository.findWithPagination(page * pageSize, pageSize);
    }

    /**
     * 根据 ID 查询
     */
    public Optional<AlarmRecord> getById(Long id) {
        return repository.findById(id);
    }

    /**
     * 查询最近的告警
     */
    public List<AlarmRecord> getRecent() {
        return repository.findTop100ByOrderByTimestampDesc();
    }

    /**
     * 按攻击类型筛选
     */
    public List<AlarmRecord> findByAttackType(String type) {
        return repository.findByAttackType(type);
    }

    /**
     * 按严重级别筛选
     */
    public List<AlarmRecord> findBySeverity(String severity) {
        return repository.findBySeverity(severity);
    }

    /**
     * 按时间范围筛选
     */
    public List<AlarmRecord> findByTimeRange(LocalDateTime start, LocalDateTime end) {
        return repository.findByTimestampBetween(start, end);
    }

    /**
     * 统计总数
     */
    public long count() {
        return repository.count();
    }

    /**
     * 删除告警记录
     */
    @Transactional
    public void deleteById(Long id) {
        repository.deleteById(id);
    }

    /**
     * 批量删除
     */
    @Transactional
    public void deleteBatch(List<Long> ids) {
        for (Long id : ids) {
            repository.deleteById(id);
        }
    }
}
