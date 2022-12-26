import Vue from 'vue';
import ElementUI from 'element-ui';
import 'element-ui/lib/theme-chalk/index.css';
import App from './App.vue'; // 就这行
// 这里是vue的新版用法，建议看下官网，3.0新增的vue文件，本质上和js文件有相同又有不同，
// 我没太用懂，但是一堆框架都做了这方面的适配（甚至很多就基于这个更新了一堆功能
Vue.use(ElementUI);

new Vue({
    el: '#app',
    render: h => h(App)
});