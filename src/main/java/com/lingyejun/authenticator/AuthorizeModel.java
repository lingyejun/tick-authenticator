package com.lingyejun.authenticator;

/**
 * 认证客户端验证码的返回对象
 *
 * @Author: lingyejun
 * @Date: 2019/3/29
 * @Describe: 
 * @Modified By:
 */
public class AuthorizeModel {

    /**
     * 认证成功或失败
     * true为认证成功
     */
    private boolean success = false;

    /**
     * 认证成功时返回的漂移窗口数
     * 如-1为客户单延迟一个窗口，+1为超前一个窗口
     */
    private int driftWindowNum;

    /**
     * 一个时间窗口的大小
     */
    private long timeStepMills;

    public boolean isSuccess() {
        return success;
    }

    public void setSuccess(boolean success) {
        this.success = success;
    }

    public int getDriftWindowNum() {
        return driftWindowNum;
    }

    public void setDriftWindowNum(int driftWindowNum) {
        this.driftWindowNum = driftWindowNum;
    }

    public long getTimeStepMills() {
        return timeStepMills;
    }

    public void setTimeStepMills(long timeStepMills) {
        this.timeStepMills = timeStepMills;
    }
}
