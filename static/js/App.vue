<template>
  <div id="app"  style="height:900px">
    <el-container style="height:100%">
      <el-aside width="150px" style="height:100%">
        <el-menu
            :default-active="$route.path"
            :router="true"

            class="el-menu-vertical-demo"
            background-color="#545c64"
            text-color="#fff"
            active-text-color="#ffd04b">
          <el-menu-item index="/login">
            <i class="el-icon-s-custom"></i>
            <span>登录</span>
          </el-menu-item>
          <el-menu-item index="/category">
            <i class="el-icon-s-grid"></i>
            <span slot="title">所有分类</span>
          </el-menu-item>

          <el-menu-item index="/book">
            <i class="el-icon-reading"></i>
            <span slot="title">所有图书</span>
          </el-menu-item>
          <el-menu-item index="4" disabled>

          </el-menu-item>
        </el-menu>
      </el-aside>
      <el-main style="height:100%">

        <router-view></router-view>

      </el-main>
    </el-container>
  </div>
</template>

<style>
.el-header, .el-footer {
  background-color: #B3C0D1;
  color: #333;
  text-align: center;
  line-height: 60px;
}

.el-aside {
  background-color: #D3DCE6;
  color: #333;
  text-align: center;
  line-height: 200px;
}

.el-main {
  background-color: #E9EEF3;
  color: #333;
  text-align: center;
  line-height: 160px;
}

body > .el-container {
  margin-bottom: 40px;
}

.el-container:nth-child(5) .el-aside,
.el-container:nth-child(6) .el-aside {
  line-height: 260px;
}

.el-container:nth-child(7) .el-aside {
  line-height: 320px;
}
</style>
