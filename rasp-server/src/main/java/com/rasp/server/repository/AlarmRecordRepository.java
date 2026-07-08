package com.rasp.server.repository;

import com.rasp.server.model.AlarmRecord;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

/**
 * 告警记录数据仓库
 */
@Repository
public interface AlarmRecordRepository extends JpaRepository<AlarmRecord, Long> {

    /** 按攻击类型查询 */
    List<AlarmRecord> findByAttackType(String attackType);

    /** 按严重级别查询 */
    List<AlarmRecord> findBySeverity(String severity);

    /** 按阻断状态查询 */
    List<AlarmRecord> findByBlocked(boolean blocked);

    /** 按时间范围查询 */
    List<AlarmRecord> findByTimestampBetween(LocalDateTime start, LocalDateTime end);

    /** 按应用名称查询 */
    List<AlarmRecord> findByAppName(String appName);

    /** 统计各攻击类型数量 */
    @Query("SELECT a.attackType, COUNT(a) FROM AlarmRecord a GROUP BY a.attackType")
    List<Object[]> countByAttackType();

    /** 统计各严重级别数量 */
    @Query("SELECT a.severity, COUNT(a) FROM AlarmRecord a GROUP BY a.severity")
    List<Object[]> countBySeverity();

    /** 按小时统计攻击趋势 */
    @Query("SELECT FUNCTION('DATE_FORMAT', a.timestamp, '%Y-%m-%d %H'), COUNT(a) " +
           "FROM AlarmRecord a WHERE a.timestamp >= :since GROUP BY FUNCTION('DATE_FORMAT', a.timestamp, '%Y-%m-%d %H')")
    List<Object[]> countByHourSince(@Param("since") LocalDateTime since);

    /** 查询最近的 N 条告警 */
    List<AlarmRecord> findTop100ByOrderByTimestampDesc();

    /** 按页码分页查询 */
    @Query(value = "SELECT * FROM rasp_alarms ORDER BY timestamp DESC LIMIT :limit OFFSET :offset",
           nativeQuery = true)
    List<AlarmRecord> findWithPagination(@Param("offset") int offset, @Param("limit") int limit);

    /** 统计总数 */
    long count();

    /** 按时间范围统计 */
    long countByTimestampBetween(LocalDateTime start, LocalDateTime end);
}
